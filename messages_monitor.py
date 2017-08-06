#!/usr/bin/python
__author__ = 'anson'
import optparse
import re
import sys
from utils.utils_cmd import execute_sys_cmd
from lib_monitor.monitor_default_format import nagios_state_to_id

class messages_check():
    def __init__(self, rex, config, type):
        self.rex = rex
        self.config = config
        self.type = type

    def run(self):
        result, infos = execute_sys_cmd('/usr/local/nagios/libexec/check_logfiles -f ' + self.config)
        v_protocol = None
        exit_state = 3
        if len(infos) > 0:
            state = infos[0].split()[0]
            if state not in nagios_state_to_id.keys():
                print infos
                sys.exit(exit_state)
            exit_state = nagios_state_to_id[state]
            if nagios_state_to_id[state] > 0:
                m_protocol = re.search(r'\(\d+ errors in ([^ ]+)\)', infos[0])
                v_protocol = m_protocol.group(1) if m_protocol else None
        else:
            sys.exit(exit_state)
        if v_protocol is not None:
            rex_dict = []
            with open(self.rex, buffering=2000000) as rex_all:
                for rex_split in rex_all:
                    rex_dict.append(rex_split)
            with open('/tmp/' + v_protocol, buffering=2000000) as file_to_check:
                for part in file_to_check:
                    for rex_rule in rex_dict:
                        m_iface = re.search(rex_rule, part)
                        v_dev = m_iface.group(1) if m_iface else 'none'
                        print v_dev
        sys.exit(exit_state)



def main():
    """
    messages_monitor.py

    unit test example
    python messages_monitor.py
    """
    parser = optparse.OptionParser(
        usage="%prog [options] [--parameter]",
        description="To monitor system log file."
    )

    parser.add_option("--config",
                      dest="config",
                      help="Config file for error extraction",
                      type="string",
                      default="/usr/local/nagios/libexec/check_log.log"
    )

    parser.add_option("--type",
                      dest="type",
                      help="Event type",
                      type="string",
                      default="disk"
    )

    parser.add_option("--rex",
                      dest="rex",
                      help="Regular Expression",
                      type="string",
                      default="/usr/local/nagios/libexec/rule.conf"
    )

    (options, args) = parser.parse_args()
    check = messages_check(options.rex, options.config, options.type)
    check.run()

if __name__ == '__main__':
    main()