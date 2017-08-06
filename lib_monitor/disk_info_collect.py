__author__ = 'anson'
import time
import os
import json
from utils.utils_sys_config import utils_sys_config
from utils.utils_cmd import execute_sys_cmd
from lib_monitor.monitor_default_format import disk_output_structure
from lib_monitor.monitor_default_format import nagios_to_event_state
from lib_monitor.monitor_default_format import send_nsca

lsscsi_cmd = 'timeout 30 lsscsi -d | grep disk'
smartctl_cmd = 'timeout 120 smartctl -A '
smartctl_enable_cmd = "timeout 30 smartctl --smart=on "
smartctl_info_cmd = "timeout 30 smartctl --info "
check_smart_json = os.path.abspath(os.path.join(os.path.dirname(__file__))) + '/check_smartdb_all.json'

disk_change_state = {
    'add': 'plug_in',
    'remove': 'plug_out'
}


class disk_info():
    def __init__(self, file, ip):
        self.file = file
        self.ip = ip
        self.disk_dict = {}

    def _collect_info(self):
        for _ in xrange(3):
            result, infos = execute_sys_cmd(lsscsi_cmd)
            if result:
                for info in infos:
                    info_split = info.split()
                    disk_info_collect = {
                        'slot': info_split[0],
                        'type': info_split[2],
                        'serial': '_'.join(info_split[3:-2]),
                        'cons_error': '0',
                        'event_sent': 'no'
                    }
                    self.disk_dict[info_split[-2]] = disk_info_collect
                break
            else:
                time.sleep(30)

    def initial_state(self):
        config_obj = utils_sys_config(self.file)
        self._collect_info()
        for key in list(self.disk_dict.keys()):
            for item in list(self.disk_dict[key].keys()):
                config_obj.add_section(key, item, self.disk_dict[key][item])

    def update_state(self):
        output = ''
        config_obj = utils_sys_config(self.file)
        old_disk_list = config_obj.get_all_sections()
        self._collect_info()
        # Find removed disk info
        disk_removed = list(set(old_disk_list).difference(set(self.disk_dict.keys())))
        for removed in disk_removed:
            tmp_output = disk_output_structure(disk_change_state['remove'], removed.split('/')[2],
                                               config_obj.get_value_by_section_keyword(removed, 'serial'))
            output = tmp_output if output == '' else tmp_output + ',' + output

        # Find added disk info
        disk_added = list(set(self.disk_dict.keys()).difference(set(old_disk_list)))
        for added in disk_added:
            tmp_output = disk_output_structure(disk_change_state['add'], added.split('/')[2],
                                               self.disk_dict[added]['serial'])
            output = tmp_output if output == '' else tmp_output + ',' + output
        if output != '':
            if not send_nsca(self.ip, 'Check_disk_plug_in_out', 3, output):
                return False
        for removed in disk_removed:
            config_obj.del_section(removed)
        for added in disk_added:
            for item in list(self.disk_dict[added].keys()):
                config_obj.add_section(added, item, self.disk_dict[added][item])
        return True


class smartctl_info():
    def __init__(self, file, disk):
        self.file = file
        self.info = {}
        self.disk = disk

    def collect(self):
        config_obj = utils_sys_config(self.file)
        disk_type = config_obj.get_value_by_section_keyword(self.disk, 'type')
        if disk_type == 'ATA' or disk_type == 'USB':
            self.info['serial'] = config_obj.get_value_by_section_keyword(self.disk, 'serial')
            self.info['dev'] = self.disk.split('/')[-1]
            result, data = execute_sys_cmd(smartctl_info_cmd + self.disk + ' | grep Enabled')
            enabled = False
            if len(data) > 0:
                if 'Enabled' in data:
                    enabled = True
            if not enabled:
                execute_sys_cmd(smartctl_enable_cmd + self.disk)
            result, data = execute_sys_cmd(smartctl_cmd + self.disk)
            if result:
                self.info['get_info'] = True
                self._parse_info(data)
            else:
                self.info['get_info'] = False
        return self.info

    def _parse_info(self, data_list):
        get_smartctl = False
        for data in data_list:
            if get_smartctl:
                data_split = data.split()
                if len(data_split) >= 10:
                    # SKIP Unknown_Attribute
                    if data_split[1] == 'Unknown_Attribute' or data_split[1] == 'Unknown_SSD_Attribute':
                        continue
                    smart_detail = {'ATTRIBUTE_NAME': data_split[1], 'FLAG': data_split[2],
                                    'VALUE': int(data_split[3]), 'WORST': int(data_split[4]),
                                    'THRESH': int(data_split[5]), 'TYPE': data_split[6],
                                    'UPDATED': data_split[7], 'WHEN_FAILED': data_split[8],
                                    'RAW_VALUE': ' '.join(data_split[9:])}
                    self.info[data_split[0]] = smart_detail
                else:
                    self.info['get_info'] = False
                    break
            elif 'ATTRIBUTE_NAME' in data:
                get_smartctl = True


class disk_status():
    def __init__(self, unit_test=False, test_json=None):
        self.smartctl_std = {}
        if unit_test:
            check_json = test_json
        else:
            check_json = check_smart_json
        with open(check_json, 'r') as f:
            self.smartctl_std = json.load(f)

    def check(self, infos):
        result_dict = {
            'output_info': '',
            'output': '',
            'nagios_state': 0
        }
        # if get info of disk error
        if infos['get_info'] is False:
            result_dict['output'] = disk_output_structure(nagios_to_event_state[1], infos['dev'], infos['serial'])
            result_dict['nagios_state'] = 1
            return result_dict

        for key in list(infos.keys()):
            if key == 'get_info' or key == 'serial' or key == 'dev':
                continue
            if key in list(self.smartctl_std['ID'].keys()) and key in list(self.smartctl_std['Threshs'].keys()):
                nagios_st, tmp_output = self._check_smart_in_json(infos['dev'], infos['serial'], infos[key], key)
                if tmp_output != '':
                    result_dict['output'] = tmp_output if result_dict['output'] == '' \
                        else tmp_output + ',' + result_dict['output']
                result_dict['nagios_state'] = nagios_st if result_dict['nagios_state'] < nagios_st\
                    else result_dict['nagios_state']
            # if it is out of thresh and this attribute is in critical section, send CRITICAL info
            elif infos[key]['VALUE'] < infos[key]['THRESH'] and infos[key]['WORST'] < infos[key]['THRESH']\
                    and key in self.smartctl_std['Critical']:
                value = str(infos[key]['VALUE']) + '_' + str(infos[key]['WORST']) + '_' + str(infos[key]['THRESH'])
                tmp_output = disk_output_structure(nagios_to_event_state[2], infos['dev'],
                                                   infos['serial'], infos[key]['ATTRIBUTE_NAME'],
                                                   value, infos[key]['RAW_VALUE'].split()[0])
                result_dict['output'] = tmp_output if result_dict['output'] == '' \
                    else tmp_output + ',' + result_dict['output']
                result_dict['nagios_state'] = 2 if result_dict['nagios_state'] < 2 else result_dict['nagios_state']
            # if it is out of thresh and this attribute is not in critical section, send WARNING info
            elif infos[key]['VALUE'] < infos[key]['THRESH'] and infos[key]['WORST'] < infos[key]['THRESH']:
                value = str(infos[key]['VALUE']) + '_' + str(infos[key]['WORST']) + '_' + str(infos[key]['THRESH'])
                tmp_output = disk_output_structure(nagios_to_event_state[1], infos['dev'],
                                                   infos['serial'], infos[key]['ATTRIBUTE_NAME'],
                                                   value, infos[key]['RAW_VALUE'].split()[0])
                result_dict['output'] = tmp_output if result_dict['output'] == '' \
                    else tmp_output + ',' + result_dict['output']
                result_dict['nagios_state'] = 1 if result_dict['nagios_state'] < 1 else result_dict['nagios_state']
            # Get performance info
            if key in self.smartctl_std['Perfs']:
                value = str(infos[key]['VALUE']) + '_' + str(infos[key]['WORST'])
                raw_value = infos[key]['RAW_VALUE'].split()[0]
                if key in list(self.smartctl_std['ID'].keys()) and key in list(self.smartctl_std['Threshs'].keys()):
                    if self.smartctl_std['ID'][key] == 'RAW_VALUE':
                        raw_value = raw_value + '_' + self.smartctl_std['Threshs'][key][0]
                    else:
                        value = value + '_' + self.smartctl_std['Threshs'][key][0].split(':')[0]
                else:
                    value = value + '_' + str(infos[key]['THRESH'])
                tmp_output = disk_output_structure('Perfs', infos['dev'], infos['serial'], infos[key]['ATTRIBUTE_NAME']
                                                   , value, raw_value)
                result_dict['output_info'] = tmp_output if result_dict['output_info'] == '' \
                    else tmp_output + ',' + result_dict['output_info']
        # If disk is ok, put normal status output
        if result_dict['output'] == '':
            result_dict['output'] = disk_output_structure(nagios_to_event_state[0], infos['dev'], infos['serial'])
        return result_dict

    def _check_smart_in_json(self, dev, serial, attribute_info, attribute_id):
        # RAW_VALUE over thresh and in critical section
        if self.smartctl_std['ID'][attribute_id] == 'RAW_VALUE' and not self._bigger_or_smaller(
                int(attribute_info['RAW_VALUE'].split()[0]),
                self.smartctl_std['Threshs'][attribute_id][0]) and attribute_id in self.smartctl_std['Critical']:
            raw_value = attribute_info['RAW_VALUE'].split()[0] + '_' + self.smartctl_std['Threshs'][attribute_id][0]
            return 2, disk_output_structure(nagios_to_event_state[2], dev,
                                            serial, attribute_info['ATTRIBUTE_NAME'],
                                            str(attribute_info['VALUE']), raw_value)
        # RAW_VALUE over thresh
        elif self.smartctl_std['ID'][attribute_id] == 'RAW_VALUE' and not self._bigger_or_smaller(
                int(attribute_info['RAW_VALUE'].split()[0]),
                self.smartctl_std['Threshs'][attribute_id][0]):
            # Over the second thresh. CRITICAL
            if not self._bigger_or_smaller(
                    int(attribute_info['RAW_VALUE'].split()[0]),
                    self.smartctl_std['Threshs'][attribute_id][1]):
                raw_value = attribute_info['RAW_VALUE'].split()[0] + '_' + self.smartctl_std['Threshs'][attribute_id][1]
                return 2, disk_output_structure(nagios_to_event_state[2], dev,
                                                serial, attribute_info['ATTRIBUTE_NAME'],
                                                str(attribute_info['VALUE']), raw_value)
            else:
                raw_value = attribute_info['RAW_VALUE'].split()[0] + '_' + self.smartctl_std['Threshs'][attribute_id][0]
                return 1, disk_output_structure(nagios_to_event_state[1], dev,
                                                serial, attribute_info['ATTRIBUTE_NAME'],
                                                str(attribute_info['VALUE']), raw_value)
        # VALUE over thresh and in critical section
        if self.smartctl_std['ID'][attribute_id] == 'VALUE' and not self._bigger_or_smaller(
                attribute_info['VALUE'], self.smartctl_std['Threshs'][attribute_id][0])\
                and attribute_id in self.smartctl_std['Critical']:
            value = str(attribute_info['VALUE']) + '_' + str(attribute_info['WORST']) + '_' + self.smartctl_std['Threshs'][attribute_id][0]
            return 2, disk_output_structure(nagios_to_event_state[2], dev,
                                            serial, attribute_info['ATTRIBUTE_NAME'],
                                            value, attribute_info['RAW_VALUE'].split()[0])
        # VALUE over thresh
        elif self.smartctl_std['ID'][attribute_id] == 'VALUE' and not self._bigger_or_smaller(
                attribute_info['VALUE'], self.smartctl_std['Threshs'][attribute_id][0]):
            # Over the second thresh. CRITICAL
            if not self._bigger_or_smaller(
                    attribute_info['VALUE'],
                    self.smartctl_std['Threshs'][attribute_id][1]):
                value = str(attribute_info['VALUE']) + '_' + str(attribute_info['WORST'])\
                        + '_' + self.smartctl_std['Threshs'][attribute_id][1]
                return 2, disk_output_structure(nagios_to_event_state[2], dev,
                                                serial, attribute_info['ATTRIBUTE_NAME'],
                                                value, attribute_info['RAW_VALUE'].split()[0])
            else:
                value = str(attribute_info['VALUE']) + '_' + str(attribute_info['WORST'])\
                        + '_' + self.smartctl_std['Threshs'][attribute_id][0]
                return 1, disk_output_structure(nagios_to_event_state[1], dev,
                                                serial, attribute_info['ATTRIBUTE_NAME'],
                                                value, attribute_info['RAW_VALUE'].split()[0])
        # WORST over thresh and in critical section
        if self.smartctl_std['ID'][attribute_id] == 'VALUE' and not self._bigger_or_smaller(
                attribute_info['WORST'], self.smartctl_std['Threshs'][attribute_id][0])\
                and attribute_id in self.smartctl_std['Critical']:
            value = str(attribute_info['VALUE']) + '_' + str(attribute_info['WORST']) + '_' + self.smartctl_std['Threshs'][attribute_name][0]
            return 2, disk_output_structure(nagios_to_event_state[2], dev,
                                            serial, attribute_info['ATTRIBUTE_NAME'],
                                            value, attribute_info['RAW_VALUE'].split()[0])
        # WORST over thresh
        elif self.smartctl_std['ID'][attribute_id] == 'VALUE' and not self._bigger_or_smaller(
                attribute_info['WORST'], self.smartctl_std['Threshs'][attribute_id][0]):
            # Over the second thresh. CRITICAL
            if not self._bigger_or_smaller(
                    attribute_info['WORST'],
                    self.smartctl_std['Threshs'][attribute_id][1]):
                value = str(attribute_info['VALUE']) + '_' + str(attribute_info['WORST'])\
                        + '_' + self.smartctl_std['Threshs'][attribute_id][1]
                return 2, disk_output_structure(nagios_to_event_state[2], dev,
                                                serial, attribute_info['ATTRIBUTE_NAME'],
                                                value, attribute_info['RAW_VALUE'].split()[0])
            else:
                value = str(attribute_info['VALUE']) + '_' + str(attribute_info['WORST'])\
                        + '_' + self.smartctl_std['Threshs'][attribute_id][0]
                return 1, disk_output_structure(nagios_to_event_state[1], dev,
                                                serial, attribute_info['ATTRIBUTE_NAME'],
                                                value, attribute_info['RAW_VALUE'].split()[0])
        return 0, ''



    def _bigger_or_smaller(self, value, thresh):
        locate = thresh.find('>')
        if locate < 0:
            if value > int(thresh) or value < 0:
                return False
        elif locate == 0:
            if value > int(thresh.split('>')[1]):
                return False
        else:
            if value < int(thresh.split('>')[0]):
                return False
        return True
