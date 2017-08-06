_author__ = 'anson'
import socket
import time
from utils.utils_cmd import execute_sys_cmd
from utils.utils_sys_config import utils_sys_config
# output to nagios

split_token = ':'

# nagios state number > Perspective state
nagios_to_event_state = {
    0: 'normal',
    1: 'abnormal',
    2: 'failure',
    3: 'abnormal'
}

# nagios state number meaning
nagios_state = {
    0: 'OK',
    1: 'WARNING',
    2: 'CRITICAL',
    3: 'UNKNOWN'
}

nagios_state_to_id = {
    'OK': 0,
    'WARNING': 1,
    'CRITICAL': 2,
    'UNKNOWN': 3
}


def node_output_structure(nagios_code, sensor_return, item, info_list=[]):
    if len(info_list) > 3:
        return sensor_return + split_token + _clean_blank(item)\
            + split_token + _clean_blank(info_list[3]) + split_token + nagios_to_event_state[nagios_code]
    else:
        return sensor_return + split_token + _clean_blank(item)\
            + split_token + 'None' + split_token + nagios_to_event_state[nagios_code]


def disk_output_structure(return_state, dev, serial, attribute='', value='', raw_value=''):
    if value == '' and raw_value == '' and attribute == '':
        return dev + split_token + return_state + split_token + '[' + serial + ']'
    else:
        return dev + split_token + return_state + split_token\
               + '[' + serial + '/' + attribute + '/' + value + '/' + raw_value + ']'


def send_nsca(ip, service_description, nagios_code, input, log_file='disk_plug_in_out.log'):
    output = '\"' + socket.gethostname() + '\t' + \
             service_description + '\t' + \
             str(nagios_code) + '\t' + input + '\"'
    # If this function will be used for udev rules run, any process need given whole path. ex: /usr/sbin/send_nsca
    result, out = execute_sys_cmd('echo -e ' + output + '| /usr/sbin/send_nsca -H ' + ip + ' -p 5667 -c /etc/nagios/send_nsca.cfg')
    config_obj = utils_sys_config('/var/log/' + log_file)
    config_obj.add_keyword('send_nsca', out)
    if not result:
        return False
    time.sleep(1)
    output = '\"' + socket.gethostname() + '\t' + \
             service_description + '\t' + \
             str(0) + '\t' + input + '\"'
    result, out = execute_sys_cmd('echo -e ' + output + '| /usr/sbin/send_nsca -H ' + ip + ' -p 5667 -c /etc/nagios/send_nsca.cfg')
    config_obj.add_keyword('send_nsca2', out)
    if not result:
        return False
    return True


def _clean_blank(tmp_str):
    return tmp_str.rstrip().lstrip().replace(' ', '_')
