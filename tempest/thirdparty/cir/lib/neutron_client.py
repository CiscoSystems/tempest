import ast
from tempest.thirdparty.cir.lib.device.devCon import lnxCon as lnxCon


class NeutronClient:

    def __init__(self, name, ip='127.0.0.1', user='localadmin', pw='ubuntu',
                 resource_file='~/devstack/openrc '):
        self.ip = ip
        self.name = name
        self.user = user
        self.pw = pw
        self.conn = None
        self.config_size = {}
        self.devType = 'linux'
        self.resource_file = resource_file
        self.send_command('ls')

    def connect(self):
        conn_info = "ssh -o \"StrictHostKeyChecking no\" {0}@{1}".format(
            self.user, self.ip)
        self.conn = lnxCon(conn_info,
                           userName=self.user,
                           pwTacacs=self.pw)
        self.conn.send_command("stty cols 254")

    def get_os_suffix(self):
        return '-' + self.devType

    def is_connected(self):
        if self.conn:
            return self.conn.is_connected()
        return False

    def execute(self, cmd, timeout=None, prompt=None, searchwindowsize=None,
                verify=1):
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

    def net_list(self):
        net_list_out = self.conn.send_command("neutron net-list")
        net_list = {}
        for line in net_list_out.splitlines():
            if line.startswith("+--") or line.startswith("| id "):
                continue
            net_data = line.strip('|').split('|')
            if len(net_data) != 3:
                continue

            net_list[net_data[0].strip()] = {
                'name': net_data[1].strip(),
                'subnet': {
                    'id': net_data[2].strip().split(" ")[0],
                    'net': net_data[2].strip().split(" ")[1],
                },
            }

        return net_list

    def net_show(self, net):
        net_show_out = self.conn.send_command(
            "neutron net-show {0}".format(net))
        net_show = {}
        for line in net_show_out.splitlines():
            if line.startswith("+--") or line.startswith("| Field "):
                continue
            device_data = line.strip('|').split('|')
            if len(device_data) != 2:
                continue

            net_show[device_data[0].strip()] = device_data[1].strip()

        return net_show

    def cisco_hosting_device_list(self):
        device_list_out = self.conn.send_command(
            "neutron cisco-hosting-device-list")
        device_list = {}
        for line in device_list_out.splitlines():
            if line.startswith("+--") or line.startswith("| id "):
                continue
            device_data = line.strip('|').split('|')
            if len(device_data) != 6:
                continue

            device_list[device_data[0].strip()] = {
                'name': device_data[1].strip(),
                'template_id': device_data[2].strip(),
                'admin_state_up': device_data[3].strip(),
                'status': device_data[4].strip(),
            }

        return device_list

    def cisco_hosting_device_show(self, hd_id):
        device_show_out = self.conn.send_command(
            "neutron cisco-hosting-device-show {0}".format(hd_id))
        device_show = {}
        for line in device_show_out.splitlines():
            if line.startswith("+--") or line.startswith("| Field "):
                continue
            device_data = line.strip('|').split('|')
            if len(device_data) != 2:
                continue

            device_show[device_data[0].strip()] = device_data[1].strip()

        return device_show

    def cisco_hosting_device_update(self, name, hd_id):
        update_out = self.conn.send_command(
            "neutron cisco-hosting-device-update --name {0} {1}".format(name,
                                                                        hd_id))
        if update_out.startswith('Updated'):
            return True
        return False

    def cisco_hosting_device_list_hosted_routers(self, hd_id):
        hosted_routers_out = self.conn.send_command(
            "neutron cisco-hosting-device-list-hosted-routers {0}".format(
                hd_id))

        rtrs_list = {}
        for line in hosted_routers_out.splitlines():
            if line.startswith("+--") or line.startswith("| id "):
                continue
            rtr_data = line.strip('|').split('|')
            if len(rtr_data) != 3:
                continue

            rtrs_list[rtr_data[0].strip()] = {
                'name': rtr_data[1].strip(),
                'external_gateway_info': ast.literal_eval(rtr_data[2].strip())
            }

        return rtrs_list

    def cisco_hosting_device_get_config(self, hd_id):
        asr_cfg = self.send_command(
            "neutron cisco-hosting-device-get-config {0}".format(hd_id))

        return asr_cfg
