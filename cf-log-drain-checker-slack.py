#!/usr/bin/env python

import json
import os
from urllib.parse import urlparse

import requests

CF_USERNAME=os.environ['CF_USERNAME']
CF_PASSWORD=os.environ['CF_PASSWORD']
CF_ENDPOINT=os.environ['CF_ENDPOINT']
SLACK_URL=os.environ['SLACK_URL']


from cloudfoundry import get_client


EXCLUDE_SPACE_KEYWORDS = ['sandbox', 'shared']
EXCLUDE_APP_KEYWORDS = ['conduit']


def redact_password_in_url(url):
    parsed_url = urlparse(url)

    if parsed_url.password:
        return url.replace(parsed_url.password, '*' * len(parsed_url.password))

    return url


if __name__ == '__main__':

    client = get_client(CF_USERNAME, CF_PASSWORD, CF_ENDPOINT)

    output = []

    for org in client.organizations.list():

        org_name = org['entity']['name']

        for space in org.spaces():
            space_name = space['entity']['name']

            if any(True for kw in EXCLUDE_SPACE_KEYWORDS if kw in space_name):
                print(f'Excluding space: {space_name}')
                continue

            for app in space.apps():

                app_name = app['entity']['name']

                if app['entity']['environment_json'] and 'DISABLE_ELK_CHECK' in app['entity']['environment_json']:
                    print(f'Excluding {org_name} / {space_name} / {app_name}due to "DISABLE_ELK_CHECK" env var')
                    continue

                if any(True for kw in EXCLUDE_APP_KEYWORDS if kw in app_name):
                    print(f'Excluding {org_name} / {space_name} / {app_name}')
                    continue

                if app['entity']['state'] == 'STARTED':
                    try:
                        for sb in app.service_bindings():
                            if sb['entity'].get('syslog_drain_url', None):
                                log_drain_url = redact_password_in_url(sb['entity']['syslog_drain_url'])
                                print(f'{org_name} / {space_name} / {app_name} FOUND {log_drain_url}')
                                break
                        else:
                            output.append(f'{org_name} / {space_name} / {app_name} NO LOG DRAIN')
                    except Exception as ex:
                        output.append(f'{org_name} / {space_name} / {app_name} ERROR RETRIEVING SERVICES')


    print('----')
    print('\n'.join(output))

    data = {
        "text": '\n'.join(output)
    }

    response = requests.post(SLACK_URL, data=json.dumps(data))
