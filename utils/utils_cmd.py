import os
import re
import time
import hashlib
import traceback
import subprocess
import socket
from datetime import datetime

import shutil
import paramiko

from utils_log import utils_log

cmd_execution_log = utils_log(name='utils_cmd_log')


class execute_ssh_cmd():
    """
    Use Paramiko to execute shell command through ssh
    """
    def __init__(self, ip, timeout=60, username=None, password=None, port=22):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.connected = False
        self.ip = ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port

    def exe(self, cmd, async=False, timeout=600, conn_retry=60):
        cmd_execution_log.logger.info('cmd: %s' % cmd)
        result_line = ''
        result_list = []
        try:
            if self.connected is False:
                conn_retry_count = 0
                while True:
                    try:
                        self.ssh.connect(self.ip,
                                         port=self.port,
                                         username=self.username,
                                         password=self.password,
                                         timeout=self.timeout)
                        self.connected = True
                        break
                    except paramiko.SSHException:
                        conn_retry_count += 1
                        if conn_retry_count >= conn_retry:
                            return False, 'Cannot connect to %s' % self.ip
                        else:
                            time.sleep(1)

            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            if async:
                return True, []
            # timeout: the process does not respond
            stdout.channel.settimeout(timeout)
            while not stdout.channel.exit_status_ready():
                result_line += stdout.channel.recv(2048)
                # timeout: the process
                stdout.channel.settimeout(timeout)
            status_code = stdout.channel.recv_exit_status()
            # Need to gobble up any remaining output after program terminates...
            while stdout.channel.recv_ready():
                result_line += stdout.channel.recv(2048)
                # timeout: the process
                stdout.channel.settimeout(timeout)
            result_list = result_line.split("\n")

            # if the last one is empty, delete it
            if len(result_list[-1]) == 0:
                result_list.remove(result_list[-1])
            # add '\n' to every one
            for _i in xrange(len(result_list)):
                result_list[_i] += "\n"

            cmd_execution_log.logger.error('output result_list:%s', result_list)
            cmd_execution_log.logger.error('status_code:%s', status_code)

            #result_list.append(status_code)

            if status_code == 0:
                return True, result_list
            else:
                result_list_tmp = stderr.readlines()
                if len(result_list_tmp) > 0:
                    result_list = result_list_tmp
                    cmd_execution_log.logger.error('error result_list:%s', result_list)
                    #result_list.append(result_list_tmp)

                return False, result_list
        except paramiko.SSHException as e:
            if self.connected is True:
                cmd_execution_log.logger.exception('Execute SSH %s failed: %s',
                                                   cmd, result_list)
            else:
                cmd_execution_log.logger.exception(
                    'Setup SSH connection to %s failed: %s',
                    self.ip, result_list)
            return False, []
        except socket.timeout as e:
            cmd_execution_log.logger.exception('Execute SSH %s timeout: %s',
                                               cmd, result_list)
            return False, result_line
        except Exception as e:
            cmd_execution_log.logger.exception(
                'Unknown Exception to ip %s: %s (%s): %s',
                self.ip, e, traceback.format_exc(), result_list)
            return False, []

    def close(self):
        self.ssh.close()


def execute_sys_cmd(cmd_string, cwd=None):
    """
    Execute shell command
    """
    p = subprocess.Popen(cmd_string,
                         cwd=cwd,
                         shell=True,
                         # 0=unbuffered,
                         # 1=line-buffered,
                         # else buffer-size
                         bufsize=0,
                         stdin=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         stdout=subprocess.PIPE)
    result = []
    while p.poll() is None:
        line = p.stdout.readline()
        result.append(line.strip('\n'))

    if p.returncode == 0:
        # check if there are any outputs.
        for line in iter(p.stdout.readline, ''):
            result.append(line.strip('\n'))
        # delete blank that the last in list
        if len(result) > 0:
            while not len(result[-1]) > 0:
                result.pop()
                if not len(result) > 0:
                    break
        cmd_execution_log.logger.debug('Execute system command:%s result:%s' % (cmd_string, result))
        return True, result
    else:
        if p.stderr is not None:
            result = [_i.strip('\n') for _i in p.stderr.readlines()]
        else:
            # check if there are any outputs.
            for line in iter(p.stdout.readline, ''):
                result.append(line.strip('\n'))
            # delete blank that the last in list
            if len(result) > 0:
                while not len(result[-1]) > 0:
                    result.pop()
                    if not len(result) > 0:
                        break
        cmd_execution_log.logger.error('Execute system command:%s failed result:%s' % (cmd_string, result))
        return False, result


def execute_pssh_cmd(cmd, host_list, timeout=120, user='root'):
    """
    Execute pssh command
    """
    # 127 - command not found
    host_str = ' -H '.join(host_list)
    cmd_string = ('pssh -l %s '
           '-O UserKnownHostsFile=/dev/null '
           '-O StrictHostKeyChecking=no '
           '-i -t %s -p 30 -H %s %s' % (user, timeout, host_str, cmd))
    cmd_execution_log.logger.debug('cmd -> %s' % cmd_string)
    cmd_success, result_buf_list = execute_sys_cmd(cmd_string)
    # Parser
    #print p.stdout.readlines()
    res_list = []
    for line in result_buf_list:
        pattern = re.compile(r'\[(?P<id>\d+)\] (?P<hour>\d+):(?P<min>\d+):(?P<sec>\d+) \[(?P<result>\w+)\] (?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
        match = pattern.match(line)
        if match:
            _d = {}
            cmd_result = match.groupdict()
            # print cmd_result
            _d['time'] = str(datetime.now())
            _d['id'] = cmd_result['id']
            _d['ip'] = cmd_result['ip']
            _d['content'] = []
            _d['cmd'] = cmd
            if cmd_result['result'] == 'SUCCESS':
                _d['success'] = True
            else:
                _d['success'] = False
            res_list.append(_d)
        else:
            if len(res_list) > 0:
                res_list[-1]['content'].append(line)
    cmd_execution_log.logger.debug('result_list -> %s' % res_list)
    return res_list


def execute_multiprocess_ssh_cmd(func, *arg, **kwargs):
    """
    Use pathos.multiprocessing to process function parallel
    """
    from pathos.multiprocessing import ProcessingPool as Pool
    pool = Pool(processes=10)  # SSH server default MaxSession is 10
    results = pool.map(func, *arg, **kwargs)
    return results


def rsync(ip, src, dest, user='root'):
    """
    Use rsync to copy files to remote node
    """
    cmd = ("rsync -avz "
           "-e 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no' "
           "%s %s@%s:%s" % (src, user, ip, dest))
    return execute_sys_cmd(cmd)

def execute_waiting_cmd(ip, wait=60, sleep=10):
    ssh_handle = execute_ssh_cmd(ip)
    for _round in xrange(wait):
        result, result_list = ssh_handle.exe('pwd')
        if result:
            break
        cmd_execution_log.logger.debug('SSH command fail, try 10 second later.')
        time.sleep(sleep)
    else:
        cmd_execution_log.logger.error('wait {0} too long, failed.'.format(ip))
        return False
    return True


class KeyPair():
    """
    Control ssh key
    """
    def __init__(self):
        home = os.path.expanduser("~")
        self.ssh_dir = '%s/.ssh' % home
        self.pri_key = '%s/id_rsa' % self.ssh_dir
        self.pub_key = '%s/id_rsa.pub' % self.ssh_dir
        self.auth_key = '%s/authorized_keys' % self.ssh_dir

    def gen_ssh_key_pair(self):
        # Already have 3 keys
        if (os.path.exists(self.pri_key) and
            os.path.exists(self.pub_key) and
            os.path.exists(self.auth_key)):
            pass
        # Only has pub_key
        elif (os.path.exists(self.pub_key) and
              not os.path.exists(self.auth_key)):
            shutil.copy2(self.pub_key, self.auth_key)
        # Don't has pri_key, generate it
        else:
            # user's sshkey
            cmd = 'mkdir -p %s ; ssh-keygen -t rsa -N "" -f %s' % (
                  self.ssh_dir, self.pri_key)
            execute_sys_cmd(cmd)
            shutil.copy2(self.pub_key, self.auth_key)
            # root's sshkey
            cmd = ('sudo rsync -r ~/.ssh /root/')
            execute_sys_cmd(cmd)
        with open(self.auth_key, 'r') as f:
            auth_key_content = f.read()
        return (auth_key_content,
                hashlib.md5(open(self.auth_key).read()).hexdigest())

    def gen_auth_key(self, md5_dig, auth_content):
        if os.path.exists(self.auth_key):
            with open(self.auth_key) as f:
                my_dig = hashlib.md5(f.read()).hexdigest()
                if md5_dig == my_dig:
                    cmd_execution_log.logger.debug('key is the same')
                else:
                    self._write_auth_key(auth_content)
        else:
            self._write_auth_key(auth_content)

    def _write_auth_key(self, auth_content):
        cmd_execution_log.logger.debug('generate authorized_keys')
        if not os.path.exists(self.ssh_dir):
            os.mkdir(self.ssh_dir)
        execute_ssh_cmd('echo "{0}" >> {1}'.format(auth_content, self.auth_key))

    def copy_key_to_root(self):
        cmd = 'sudo rsync -r ~/.ssh /root/'
        execute_sys_cmd(cmd)


def execute_cmd_in_cluster(command_string, node_ips, user):
    results = {}
    result_list = execute_pssh_cmd('"%s"' % command_string, node_ips, user=user)

    for result in result_list:
        ip_addr = result['ip'].replace("\n", "")
        results[ip_addr] = result['success']

        if result['success'] != True:
            cmd_execution_log.logger.info(
                'Fail to execute (%s) on Node (%s): %s' %
                (command_string, ip_addr, result['content']))

    return results


if __name__ == '__main__':
    ssh_test = execute_ssh_cmd('127.0.0.1', username='test', password='test')
    result, log = ssh_test.exe('ls')
    ssh_test.close()
    cmd_result = execute_sys_cmd('ls')
    print result
    cmd_result = execute_pssh_cmd('ls', ['127.0.0.1'])
    print result
