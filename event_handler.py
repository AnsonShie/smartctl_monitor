#!/usr/bin/python
__author__ = 'anson'
import optparse
import json
from lib_monitor.event_handler_default import api_setting, gen_node_event, gen_disk_event, gen_network_event
from requests.exceptions import ConnectionError

class handle_event:
    def __init__(self, api):
        self.api = api

    def node(self, ip, state_id, event_input):
        for event in event_input:
            json_body, api_url = gen_node_event(ip, state_id, event)
            # If both is None, it means this event does not need to be sent.
            if json_body is None and api_url is None:
                continue
            try:
                res = self.api.post(api_url, data=json.dumps(json_body))
                if res.status_code != 200:
                    return False
            except ConnectionError:
                return False
            # If nagios state is ok, only send normal event once.
            if state_id == 0:
                break
        return True

    def disk(self, ip, event_input):
        for event in event_input:
            if event == "none":
                continue
            json_body, api_url = gen_disk_event(ip, event)
            # If both is None, it means this event does not need to be sent.
            if json_body is None and api_url is None:
                continue
            try:
                res = self.api.post(api_url, data=json.dumps(json_body))
                if res.status_code != 200:
                    return False
            except ConnectionError:
                return False
        return True

    def network(self, ip, state_id, event_input):
        for event in event_input:
            json_body, api_url = gen_network_event(ip, event)
            # If both is None, it means this event does not need to be sent.
            if json_body is None and api_url is None:
                continue
            try:
                res = self.api.post(api_url, data=json.dumps(json_body))
                if res.status_code != 200:
                    return False
            except ConnectionError:
                return False
        return True


def foo_callback(option, opt, value, parser):
    setattr(parser.values, option.dest, value.split(','))

def main():
    """
    event_handler.py [--type] [--input]
    """
    parser = optparse.OptionParser(
        usage="%prog [options] [--parameter]",
        description="Event handler for nagios state change"
    )

    parser.add_option("--ip",
                      dest="ip",
                      help="Node ip",
                      type="string",
                      default="127.0.0.1"
    )

    parser.add_option("-t", "--type",
                      dest="type",
                      help="Node, disk or network event",
                      type="string",
                      default="node"
    )

    parser.add_option("--input",
                      dest="input",
                      help="Get output from monitor",
                      type="string",
                      action='callback',
                      callback=foo_callback
    )

    parser.add_option("--long_input",
                      dest="longinput",
                      help="Get long_output from monitor",
                      type="string",
                      action='callback',
                      callback=foo_callback
    )

    parser.add_option("-s", "--state",
                      dest="stateID",
                      help="host state ID (default: 0)",
                      type="int",
                      default=0
    )

    parser.add_option("--hoststatetype",
                      dest="statetype",
                      help="host state type (default: none)",
                      default=None
    )

    (options, args) = parser.parse_args()

    api = api_setting()
    event = handle_event(api.manager())

    if options.statetype == 'HARD' and options.type == 'node':
        event.node(options.ip, options.stateID, options.input)
    elif options.statetype == 'HARD' and options.type == 'disk' and options.stateID == 0:
        event.disk(options.ip, options.longinput)
    elif options.statetype == 'HARD' and options.type == 'disk' and options.stateID == 3:
        event.disk(options.ip, options.input)
    elif options.statetype == 'HARD' and options.type == 'network':
        event.network(options.ip, options.stateID, options.input)

if __name__ == '__main__':
    main()