#!/usr/bin/python
__author__ = 'anson'
import optparse
import os.path
from lib_monitor.disk_info_collect import disk_info
from utils.utils_sys_config import utils_sys_config

def main():
    parser = optparse.OptionParser(
        usage="%prog [options] [--parameter]",
        description="To monitor system state using ipmitool."
    )

    parser.add_option("-s", "--state",
                      dest="state",
                      help="In order to store system state",
                      type="string",
                      default='/var/log/disk_info.dat'
    )

    parser.add_option("--ip",
                      dest="ip",
                      help="Node ip",
                      type="string",
                      default="192.168.136.254"
    )

    (options, args) = parser.parse_args()

    new_disk_info = disk_info(options.state, options.ip)
    if os.path.isfile(options.state):
        output = new_disk_info.update_state()
        config_obj = utils_sys_config('/var/log/disk_plug_in_out.log')
        config_obj.add_keyword('update_state_output', output)
    else:
        new_disk_info.initial_state()
        config_obj = utils_sys_config('/var/log/disk_plug_in_out.log')
        config_obj.add_keyword('initial_state_output', 'initial')

if __name__ == '__main__':
    main()