from tempest.thirdparty.cir.lib.device.devCon import nxosCon


class NxSwitch:

    def __init__(self, name, ip, user, pw):
        self.name = name
        self.ip = ip
        self.user = user
        self.pw = pw

        self.conn = None
        self.config_size = {}
        self.devType = 'nxos'
        self.connect()

    def connect(self):
        conn_info = "ssh -o \"StrictHostKeyChecking no\" {0}@{1}".format(self.user, self.ip)
        self.conn = nxosCon(conn_info,
                            userName=self.user,
                            pwTacacs=self.pw)

    def close(self, force=True):
        self.conn.close(force=force)

    def get_os_suffix(self):
        return '-' + self.devType

    def send_command(self, cmd):
        if self.conn is None:
            self.connect()

        return self.conn.send_command(cmd)

    def execute(self, show_cmd):
        return self.send_command(show_cmd)

    def is_connected(self):
        return self.conn.is_connected()

