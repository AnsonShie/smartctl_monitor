#!/usr/bin/python
__author__ = 'anson'
import optparse
import os
import sys
from utils.utils_cmd import execute_sys_cmd
from utils.utils_sys_config import utils_sys_config
from lib_monitor.disk_info_collect import smartctl_info, disk_status
from lib_monitor.monitor_default_format import nagios_state
from lib_monitor.monitor_default_format import send_nsca

class smartctl_check():
    def __init__(self, file, recheck):
        self.file = file
        self.disk_dict = {}
        self.recheck = recheck

    def run(self, unit_test=False, test_json=None, ip="192.168.136.254"):
        config_obj = utils_sys_config(self.file)
        disk_list = config_obj.get_all_sections()
        exit_state = 0
        output = ''
        output_info = ''
        state = disk_status(unit_test, test_json)
        nsca_send = False
        for disk in disk_list:
            get_smart = smartctl_info(self.file, disk)
            info = get_smart.collect()
            if len(info) != 0:
                report = state.check(info)
                exit_state = report['nagios_state'] if exit_state < report['nagios_state'] else exit_state
                # output_info print Perfs and non-ok info
                output_info = report['output_info'] if output_info == '' \
                    else report['output_info'] + ',' + output_info
                if report['output'] != '':
                    output_info = report['output'] if output_info == '' \
                        else report['output'] + ',' + output_info
                if report['nagios_state'] > 0:
                    cons_error = config_obj.get_value_by_section_keyword(disk, 'cons_error')
                    event_sent = config_obj.get_value_by_section_keyword(disk, 'event_sent')
                    if int(cons_error) < self.recheck:
                        config_obj.update_section_keyvalues(disk, {'cons_error': str(int(cons_error)+1)})
                    elif event_sent == 'no':
                        config_obj.update_section_keyvalues(disk, {'event_sent': 'yes'})
                        output = report['output'] if output == '' else report['output'] + ',' + output
                        nsca_send = True
                else:
                    config_obj.update_section_keyvalues(disk, {'cons_error': '0'})
                    config_obj.update_section_keyvalues(disk, {'event_sent': 'no'})
                    output = report['output'] if output == '' else report['output'] + ',' + output
        if exit_state > 0 and nsca_send:
            send_nsca(ip, 'smartctl', 3, output)
        print nagios_state[exit_state] + ' - ' + output_info
        print output
        sys.exit(exit_state)


def main():
    """
    smartctl_monitor.py [--state]

    unit test example
    python smartctl_monitor.py --unit_test --test_json /home/anson/system-monitor/unit_test/smartctl_test_failure/fake_smartdb_all.json
    """
    parser = optparse.OptionParser(
        usage="%prog [options] [--parameter]",
        description="To monitor disk state using smartctl."
    )

    parser.add_option("-s", "--state",
                      dest="state",
                      help="In order to store system state",
                      type="string",
                      default='/var/log/disk_info.dat'
    )

    parser.add_option("--unit_test",
                      dest="unit_test",
                      help="Enable unit_test",
                      default=False,
                      action='store_true'
    )

    parser.add_option("--test_json",
                      dest="test_json",
                      help="Fake json file to make failure or abnormal result.",
                      default=None
    )

    parser.add_option("--ip",
                      dest="ip",
                      help="Node ip",
                      type="string",
                      default="192.168.136.254"
    )

    parser.add_option("--recheck",
                      dest="recheck",
                      help="The times of recheck",
                      type="int",
                      default=1
    )

    (options, args) = parser.parse_args()

    # initial update disk status
    execute_sys_cmd(os.path.abspath(os.path.join(os.path.dirname(__file__))) + '/disk_plug_in_out.py -s ' + options.state)
    smartctl = smartctl_check(options.state, options.recheck)
    smartctl.run(options.unit_test, options.test_json, options.ip)

if __name__ == '__main__':
    main()