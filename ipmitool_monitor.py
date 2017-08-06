#!/usr/bin/python
__author__ = 'anson'
import optparse
import time
import sys

from utils.utils_sys_config import utils_sys_config
from utils.utils_cmd import execute_sys_cmd
from lib_monitor.ipmitool_monitor_default import *
from lib_monitor.monitor_default_format import node_output_structure, nagios_state


class ipmitool_schedule():
    def __init__(self, config):
        self.config = config

    def run(self, unit_test=False, test_script=None):
        output = ''
        logoutput = ''
        state = 0  # initail nagios state is OK
        for i in range(len(Sensors)):
            # Collection sensor information
            result, infos = self._parse_ipmitool_result(i, self.config, unit_test, test_script)
            if result:
                for key in list(infos.keys()):
                    # Check sensor type nagios state
                    tmp_state, tmp_output = self._check_state(key, infos[key], Sensors_return[i])
                    state = tmp_state if tmp_state > state else state
                    if tmp_state > 0:
                        logoutput = ' - ' + tmp_output if logoutput == '' else logoutput + ',' + tmp_output
                    output = tmp_output if output == '' else tmp_output + ',' + output
            # ipmitool collect information fail
            else:
                print "UNKNOWN"
                print node_output_structure(3, 'ipmitool', 'wrong_information')
                sys.exit(3)
        print nagios_state[state] + logoutput
        print output
        sys.exit(state)

    def _parse_ipmitool_result(self, sensor_num, config, unit_test=False, test_script=None):
        if config is None:
            config = '/tmp/' + Sensors_return[sensor_num] + '.log'
        config_obj = utils_sys_config(config)
        config_obj.add_section(Sensors_return[sensor_num], 'time', time.time())
        if unit_test:
            result, infos = execute_sys_cmd(test_script + Sensors_return[sensor_num] + '.log')
        else:
            result, infos = execute_sys_cmd(ipmitool_cmd + Sensors[sensor_num])
        data = {}
        if result:
            for info in infos:
                info_split = info.split('|')
                # Format is not true
                if len(info_split) != 5:
                    config_obj.add_section(Sensors_return[sensor_num], 'get_info', 'False')
                    config_obj.add_section(Sensors_return[sensor_num], info_split[0], info)
                    return False, data
                else:
                    value = info_split[1] + '|' + info_split[2] + '|' + info_split[3] + '|' + info_split[4]
                    config_obj.add_section(Sensors_return[sensor_num], info_split[0].rstrip(), value)
                    data[info_split[0].rstrip()] = value
        else:
            config_obj.add_section(Sensors_return[sensor_num], 'get_info', 'False')
            for info in infos:
                info_split = info.split('|')
                config_obj.add_section(Sensors_return[sensor_num], info_split[0], info)
            return False, data
        config_obj.add_section(Sensors_return[sensor_num], 'get_info', 'True')
        return True, data

    def _check_state(self, item, info, sensor_return):
        info_list = info.split('|')
        for sdr_state in sdr_state_list:
            if sdr_state in info_list[1]:
                output = node_output_structure(sdr_state_num[sdr_state], sensor_return, item, info_list)
                return sdr_state_num[sdr_state], output
        return 3, node_output_structure(3, 'ipmitool', 'wrong_information')

def main():
    """
    ipmitool_monitor.py [--log] [--sensor]

    unit-test example
    sudo /home/persp/system-monitor/ipmitool_monitor.py  --unit_test --test_script 'cat /home/persp/system-monitor/unit_test/ipmitool_test_abnormal/'
    """
    parser = optparse.OptionParser(
        usage="%prog [options] [--parameter]",
        description="To monitor system state using ipmitool."
    )

    parser.add_option("-l", "--log",
                      dest="log",
                      help="In order to store system state",
                      default=None
    )

    parser.add_option("--unit_test",
                      dest="unit_test",
                      help="Enable unit_test",
                      default=False,
                      action='store_true'
    )

    parser.add_option("--test_script",
                      dest="test_script",
                      help="Script to read the test information. ex: 'cat /home/persp/test/.' "
                           "it means temperature.log, power_supply.log, voltage.log "
                           "and fan.log at /home/persp/test/ for testing",
                      default=None
    )

    (options, args) = parser.parse_args()

    ipmi = ipmitool_schedule(options.log)
    if options.unit_test:
        ipmi.run(options.unit_test, options.test_script)
    else:
        ipmi.run()



if __name__ == '__main__':
    main()