import re
import tempest.thirdparty.cir.lib.asr_exceptions as asr_exceptions
from oslo_log import log as logging
from tempest.thirdparty.cir.lib.device.devCon import lnxCon as lnxCon

LOG = logging.getLogger(__name__)
LOG.debug("TestASRStandBy")

class DirectorClient:

    def __init__(self, name, ip='127.0.0.1', user='root', pw='cisco123',
                 resource_file='~/stackrc ', logfile=None):
        self.ip = ip
        self.name = name
        self.user = user
        self.pw = pw
        self.conn = None
        self.config_size = {}
        self.devType = 'linux'
        self.resource_file = resource_file
        self.logfile = logfile
        self.send_command('ls')
        self.error_re = re.compile(r'.*ERROR.*')

    def connect(self):
        self.conn_info = "ssh -o ServerAliveInterval=100 {0}@{1}".format(
            self.user, self.ip)
        self.conn = lnxCon(self.conn_info,
                           userName=self.user,
                           pwTacacs=self.pw,
                           logfile=self.logfile)

    def get_os_suffix(self):
        return '-' + self.devType

    def is_connected(self):
        if self.conn:
            return self.conn.is_connected()
        return False

    def execute(self, cmd, timeout=None, prompt=None,
                searchwindowsize=None, verify=1):
        if self.conn is None:
            self.connect()

        return self.conn.execute(cmd, timeout=timeout, prompt=prompt,
                                 searchwindowsize=searchwindowsize,
                                 verify=verify)

    def send_command(self, cmd):
        if self.conn is None:
            self.connect()
            self.send_command('source ' + self.resource_file + ' admin admin')

        return self.conn.send_command(cmd)

    def nova_list(self):
        nova_list_out = self.conn.send_command("nova list")
        error_check = self.error_re.match(nova_list_out)
        if error_check:
            msg = "ERROR: nova lise: {0}".format(nova_list_out)
            raise asr_exceptions.ASRTestException(msg)

        nova_list = {}
        for line in nova_list_out.splitlines():
            if line.startswith("+--") or line.startswith("| ID "):
                continue
            nova_data = line.strip('|').split('|')
            if len(nova_data) != 6:
                continue

            nova_list[nova_data[0].strip()] = {
                'name': nova_data[1].strip(),
                'status': nova_data[2].strip(),
                'task-state': nova_data[3].strip(),
                'power-state': nova_data[4].strip(),
                'networks': nova_data[5].strip(),
            }

        return nova_list

    def get_ip(self, node_name):
        nova_nodes = self.nova_list()
        for node_id in nova_nodes.keys():
            if nova_nodes[node_id]['name'] in node_name:
                if 'ctlplane' in nova_nodes[node_id]['networks']:
                    return nova_nodes[node_id]['networks'][9:]
                else:
                    return nova_nodes[node_id]['networks']

    def run_cmd_on(self, host, target_cmd):
        cmds = ["", 'su - stack', 'ssh heat-admin@{0}'.format(host), ""]
        self.conn.disconnect()
        self.conn = None
        self.connect()
        self.send_command(target_cmd)
        for cmd in cmds:
            self.send_command(cmd)

        cmd_out = self.send_command(target_cmd)

        for i in range(0, 2):
            try:
                self.send_command('exit')
            except UnicodeDecodeError as e:
                pass
        self.conn.disconnect()
        self.conn = None
        self.connect()
        return cmd_out




