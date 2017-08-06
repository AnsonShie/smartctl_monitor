__author__ = 'anson'
import requests
from monitor_default_format import split_token

url = "http://192.168.136.254"

send_event_state = {
    'ok': ['normal'],
    'non-ok': ['abnormal', 'failure']
}

class api_setting():
    """ Use Paramiko to execute shell command through ssh"""

    def __init__(self):
        self.manager_url = requests.session()

    def manager(self):
        self.manager_url.headers.update({'Authorization': 'Token 993274943e8a43731b8f35862a7417de3a230411'})
        self.manager_url.headers.update({'Content-Type': 'application/json'})
        self.manager_url.headers.update({'SERVICE_TYPE': 'appliance'})
        return self.manager_url


def gen_disk_event(ip, event):
    json_body = {
        "node_ip": str(ip),
        "event_type": "disk_event",
    }
    node_event_api = "/v1/event/disk/"
    json_body["event_status"] = event
    return json_body, url + node_event_api


def gen_network_event(ip, event):
    json_body = {
        "node_ip": str(ip),
        "event_type": "network_event",
    }
    node_event_api = "/v1/event/network/"
    event_split = event.split('_')
    event_out = ','.join(event_split)
    json_body["event_status"] = event_out
    return json_body, url + node_event_api


def gen_node_event(ip, state_id, event):
    json_body = {
        "node_ip": str(ip),
        "event_type": "node_event",
    }
    node_event_api = "/v1/event/node/"
    # If monitor return ok state, send normal event
    if state_id == 0:
        json_body["event_status"] = "node:node:normal"
        return json_body, url + node_event_api
    # If monitor return non-ok state, send the sensor type event that the sensor is non-ok
    elif state_id > 0 and event.split(split_token)[3] != send_event_state['ok'][0]:
        event_split = event.split(split_token)
        json_body["event_status"] = event_split[0] + split_token + event_split[1]\
                                    + split_token + event_split[3]
        return json_body, url + node_event_api
    # If monitor return non-ok state, skip sensor type that the state is ok
    else:
        return None, None