#!/usr/bin/env python
import optparse
import pymnl
import traceback
import time
import re
import sys
import threading
import uuid
from pymnl.nlsocket import Socket
from pymnl.message import Payload
from pymnl.attributes import AttrParser
from struct import calcsize, unpack
from utils.utils_log import utils_log
from utils.utils_cmd import execute_sys_cmd
from lib_monitor.monitor_default_format import send_nsca

# Netlink constants
RTMGRP_LINK = 1
IFF_UP = 0x1
IFF_RUNNING = 0x40
IFLA_IFNAME = 3
IFLA_MTU = 4

_re_interface_name = re.compile(r'eth\d+|bond\d+')
_logger = utils_log('network_monitor').logger
_dev_notify = dict()  # Used for check whether notify is obsolete


def parse_link_msg(payload):
    """
    Parse link level specific information
    :param payload:
    :return:
    """
    content_format = 'BBHiII'
    len_format = calcsize(content_format)
    content = payload[:len_format]
    family, pad, type_, index, flags, change = unpack(content_format, content)
    ifinfo= {'family': family,
             'type': type_,
             'index': index,
             'flags': flags,
             'change': change,
             'payload': payload[len_format:],  # Remain data
             }
    return ifinfo


def notify_status(notify_id, device, up, link, speed, ip):
    """
    Notify platform manager with status os network interface
    """

    status = 'up' if up is True else 'down'
    link = 'linked' if link else 'unlinked'
    output = '_'.join([device, status, link, speed])
    for _ in xrange(60):
        if notify_id != _dev_notify[device]:
            _logger.info('Notify obsolete. %s', output)
            return

        _logger.info('Notify message %s', output)
        if send_nsca(ip, "Check_interface_state", 1, output, 'check_interface.log'):
            break
        _logger.error('Notify not complete, platform manager is not ready. [%s]', sys.exc_info()[0])
        time.sleep(30)
    else:
        _logger.error('Notify device status failed')


def monitor_device(ip):
    sock = Socket(pymnl.NETLINK_ROUTE)
    sock.bind(pymnl.nlsocket.SOCKET_AUTOPID, RTMGRP_LINK)
    _logger.info('Start listening netlink RTMGRP_LINK')
    try:
        while True:
            msg_list = sock.recv()
            for msg in msg_list:
                if msg.get_errno():
                    _logger.error((msg.get_errstr()))
                    continue

            link = parse_link_msg(msg.get_payload().get_binary())
            ifla_payload = Payload(link['payload'])
            attr_parser = AttrParser(ifla_payload)
            attr_if_name = [a for a in attr_parser.get_attrs() if a.get_type() == IFLA_IFNAME]
            if not attr_if_name:
                _logger.info('Cannot get interface name attribute')
                continue

            notify_param = dict(device=attr_if_name[0].get_str_stripped())
            if not _re_interface_name.match(notify_param['device']):
                continue

            # notify_msg['running'] = True if link['flags'] & IFF_RUNNING else False
            notify_param['up'] = True if link['flags'] & IFF_UP else False
            is_link, _ = execute_sys_cmd('sudo ethtool {0} | grep "Link detected: yes"'.format(notify_param['device']))
            notify_param['link'] = True if is_link else False
            check, result = execute_sys_cmd('sudo ethtool {0} | grep "Speed"'.format(notify_param['device']))
            speed = None
            if check:
                m_speed = re.search(r'Speed:\s*([\d]+)Mb/s', result[0])
                speed = m_speed.group(1) if m_speed else None
                speed = str(float(speed)/1000) if speed > 0 else '0'
            notify_param['speed'] = speed if speed is not None else None
            _logger.info(notify_param)

            # Notify platform manager
            notify_id = uuid.uuid4()
            _dev_notify[notify_param['device']] = notify_id
            notify_param['notify_id'] = notify_id
            notify_param['ip'] = ip
            threading.Thread(target=notify_status, kwargs=notify_param).start()
    except:
        traceback.print_exc()
        sock.close()


if __name__ == '__main__':
    parser = optparse.OptionParser(
        usage="%prog [options] [--parameter]",
        description="To monitor network interface state."
    )

    parser.add_option("--ip",
                      dest="ip",
                      help="Node ip",
                      type="string",
                      default="192.168.136.254"
    )

    (options, args) = parser.parse_args()

    monitor_device(options.ip)
