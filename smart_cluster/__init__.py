import requests
from flask_restx import Namespace
import pprint
import json

from openstack.exceptions import HttpException

namespace = Namespace(
    name="smart-cluster",
    description="AutoScaling 정책 정의"
)

pp = pprint.PrettyPrinter()


def get_alarm(auth_token, receiver_id):
    if not receiver_id:
        raise ValueError("name can't be null")

    if not auth_token:
        raise ValueError("auth_key can't be null")

    url = "http://192.168.15.40:8042/v2/alarms?q.field=name&q.op=eq&q.value=%s" % receiver_id

    headers = {
        'X-Auth-Token': auth_token
    }

    response = requests.request("GET", url, headers=headers)

    alarm_list = response.json()

    return alarm_list[0] if alarm_list else None


def create_or_update_alarm(auth_token, data, alarm_id=None):
    if not auth_token:
        raise ValueError("auth_token can't be null")

    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Token': auth_token
    }

    response = None
    if alarm_id:
        url = "http://192.168.15.40:8042/v2/alarms/%s" % alarm_id

        response = requests.request("PUT", url, data=json.dumps(data), headers=headers)
    else:
        if not auth_token:
            raise ValueError("auth_token can't be null")

        url = "http://192.168.15.40:8042/v2/alarms"

        response = requests.request("POST", url, data=json.dumps(data), headers=headers)

    if not 200 <= response.status_code < 300:
        print("[{url}][{status_code}] {contents}".format(url=response.url, status_code=response.status_code,
                                                         contents=response.text))
        raise HttpException("error creating alarm")


def delete_alarm(auth_token, receiver_id):
    if not receiver_id:
        raise ValueError("receiver_id can't be null")

    if not auth_token:
        raise ValueError("auth_token can't be null")

    alarm = get_alarm(auth_token, receiver_id)

    if alarm:
        url = "http://192.168.15.40:8042/v2/alarms/%s" % alarm['alarm_id']

        headers = {
            'X-Auth-Token': auth_token
        }

        requests.request("DELETE", url, headers=headers)