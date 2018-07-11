import re
import time
import subprocess
import pexpect
import parsergen as pg
import tempest.thirdparty.cir.lib.asr_exceptions as asr_exceptions
import tempest.thirdparty.cir.lib.pg.vlan as vlan
import tempest.thirdparty.cir.lib.pg.interface_counters as interface_counters
import tempest.thirdparty.cir.lib.pg.intf as intf
import tempest.thirdparty.cir.lib.pg.ip_nat_translations as \
    ip_nat_translations
import tempest.thirdparty.cir.lib.pg.ip_nat_translations_totals as \
    ip_nat_translations_total
import tempest.thirdparty.cir.lib.pg.netconf_counters as netconf_counters
import tempest.thirdparty.cir.lib.pg.vrf_counters as vrf_counters
import tempest.thirdparty.cir.lib.pg.vrf as vrf
import tempest.thirdparty.cir.lib.pg.standby_delay as standby_delay
import tempest.thirdparty.cir.lib.pg.standby_intf as standby_intf
import tempest.thirdparty.cir.lib.pg.standby_nbrs as standby_nbrs
import tempest.thirdparty.cir.lib.pg.standby_redirects as standby_redirects
#import tempest.thirdparty.cir.lib.pg.standby_brief as standby_brief
import tempest.thirdparty.cir.lib.pg.standby_brief_multiline as standby_brief
import tempest.thirdparty.cir.lib.pg.ip_nat_pool as ip_nat_pool
import tempest.thirdparty.cir.lib.pg.ip_access_list as ip_access_list
import tempest.thirdparty.cir.lib.pg.ip_route_vrf as ip_route_vrf
import tempest.thirdparty.cir.lib.pg.ip_sub_interface as ip_sub_interface
import tempest.thirdparty.cir.lib.pg.nc_netlist as nc_netlist

from oslo_log import log as logging
from tempest.lib import exceptions
from tempest import config as tempest_conf
from tempest import test as test
from tempest.thirdparty.cir.lib.device.devCon import iosCon as iosCon
from tempest.thirdparty.cir.lib.device.devCon import lnxCon as lnxCon


CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("ASR")


class ASR:

    def __init__(self, name, ip, user, pw, external_intf, internal_intf,
                 ts_ip=None, ts_port=None, ts_prompt=None, ts_pw=None):
        self.name = name
        self.ip = ip
        self.name = ip
        self.user = user
        self.pw = pw
        self.ts_ip = ts_ip
        self.ts_port = ts_port
        self.ts_prompt = ts_prompt
        self.ts_pw = ts_pw
        self.external_intf = external_intf
        self.external_intf_sh = external_intf
        if self.external_intf.startswith("TenGigabitEthernet"):
            self.external_intf_sh = self.external_intf.replace(
                "TenGigabitEthernet", "Te")

        if self.external_intf.startswith("GigabitEthernet"):
            self.external_intf_sh = self.external_intf.replace(
                "GigabitEthernet", "Gi")

        if self.external_intf.startswith("Port-channel"):
            self.external_intf_sh = self.external_intf.replace("Port-channel",
                                                               "Po")

        self.internal_intf = internal_intf
        self.internal_intf = internal_intf
        if self.internal_intf.startswith("TenGigabitEthernet"):
            self.internal_intf_sh = self.internal_intf.replace(
                "TenGigabitEthernet", "Te")

        if self.internal_intf.startswith("GigabitEthernet"):
            self.internal_intf_sh = self.internal_intf.replace(
                "GigabitEthernet", "Gi")

        if self.internal_intf.startswith("Port-channel"):
            self.internal_intf_sh = self.internal_intf.replace("Port-channel",
                                                               "Po")

        self.conn = None
        self.console = None
        self.config_size = {}
        self.devType = 'ios'

    def connect(self):
        conn_info = "ssh {0}@{1}".format(self.user, self.ip)
        self.conn = iosCon(conn_info,
                           userName=self.user,
                           pwTacacs=self.pw)

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

        return self.conn.send_command(cmd)

    # Establish a console connection via the terminal server
    def ts_console(self):
        the_prompt = r'[\w:-~\]\)][\$|#|>|?|:][\s]*$'
        conn_info = "telnet {0}".format(self.ts_ip)
        self.console = lnxCon(conn_info,
                              prompt=the_prompt,
                              userName=None,
                              pwTacacs=self.ts_pw,
                              searchwindowsize=100)

        self.console.execute("", prompt=the_prompt)
        cmd = self.ts_port
        self.console.execute(cmd, prompt=the_prompt)
        self.console.execute("cisco123", prompt=the_prompt)
        self.console.execute("\r\n", prompt=the_prompt)
        self.console.execute('enable', prompt=the_prompt)
        self.console.execute("CTO1234!", prompt=the_prompt)
        self.console.execute("", prompt=the_prompt)
        self.console.devType = 'ios'

    # Validate if there is a console connection
    def console_connected(self):
        if self.console:
            return self.console.console_connected()
        return False

    # Execute a command via the console connection
    def console_execute(self, cmd, timeout=None, prompt=None,
                        searchwindowsize=None, verify=1):
        if self.console is None:
            self.ts_console()

        return self.console.execute(cmd, timeout=timeout, prompt=prompt,
                                    searchwindowsize=searchwindowsize,
                                    verify=verify)

    # Send a command via the console connection
    def console_send_command(self, cmd):
        if self.console is None:
            self.ts_console()

        return self.console.send_command(cmd)

    def clear_netconf_counters(self):
        self.send_command('clear netconf counters')

    def record_cfg_size(self, id):
        if id in self.config_size:
            msg = "ID {0} already in cfg_size".format(id)
            raise exceptions.Conflict(msg)

        self.send_command('')
        size_string = self.send_command("show run | inc Current configuration")
        size_string = size_string.strip()
        cfg_size_re = re.compile(r'Current configuration\s+:\s+(\d+)')
        cfg_size_match = cfg_size_re.match(size_string)
        if cfg_size_match:
            self.config_size[id] = cfg_size_match.group(1)
            return cfg_size_match.group(1)
        return 0

    def delete_cfg_size_record(self, id):
        if id in self.config_size:
            del self.config_size[id]

    def get_cfg_size(self, id):
        if id not in self.config_size:
            msg = ("Attempted to retrieve key {0} from ASR {1} config sizes: "
                   "Key not found".format(id, self.name))
            raise KeyError(msg)

        return self.config_size[id]

    def reboot(self, wait=True, timeout=600):
        self.conn.execute('reload', prompt=r'[\w:-~\]\)][\$|#|>|?|:][\s]*$')
        resp = self.send_command("")
        last_line = resp.split("\n")[-1]

        save_re = re.compile(
            r'.*System configuration has been modified.+Save.+yes/no.*')
        if save_re.match(last_line):
            try:
                self.send_command("no\n\n")
            except Exception:
                pass

        try:
            self.conn.disconnect()
        except Exception:
            pass

        if wait is True:
            time.sleep(180)
            try:
                self.ping_ip_address(self.ip,
                                     should_succeed=False,
                                     ping_timeout=timeout)
            except Exception:
                pass

            try:
                time.sleep(180)
            except Exception:
                pass

            for i in range(0, 3):
                try:
                    self.connect()
                    break
                except Exception:
                    time.sleep(60)


    def save_cfg(self, name):
        cmd = "copy running-config bootflash:{0}".format(name)
        self.conn.execute(cmd, prompt=r'[\w:-~\]\)][\$|#|>|?][\s]*$')
        self.send_command("")

    def del_cfg(self, name):
        self.send_command('delete /force bootflash:{0}'.format(name))

    def interface_state(self, state):
        self.send_command('config t')
        self.send_command("interface {0}".format(self.internal_intf))
        if state == 'down':
            self.send_command('shutdown')
        else:
            self.send_command('no shutdown')
        self.send_command('exit')
        self.send_command('exit')

    def mgmt_intf_state(self, state):
        self.console_send_command("")
        self.console_send_command('config t')
        self.console_send_command('interface gig 0')
        if state == 'down':
            self.console_send_command('shutdown')
        elif state == 'up':
            self.console_send_command('no shutdown')
        self.console_send_command('end')

    def ping_ip_address(self, ip_address, should_succeed=True,
                        ping_timeout=None):
        timeout = ping_timeout or CONF.compute.ping_timeout
        cmd = ['ping', '-c1', '-w1', ip_address]

        def ping():
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.communicate()
            return (proc.returncode == 0) == should_succeed

        return test.call_until_true(ping, timeout, 1)

    def clear_traffic_counters(self, segment_id):
        self.send_command("clear vlan {0}".format(segment_id))

    def wait_for_standby(self, seg_ids, max_time=180, sleep_for=5):
        start_time = time.time()
        current_time = time.time()
        timeout = current_time + max_time
        intf = self.internal_intf_sh + "." + str(seg_ids[0])
        while current_time < timeout:

            attr_values = [('standby-brief.intf', intf), ]
            pg_sb = pg.oper_fill(self.conn,
                                 "SHOW_STANDBY_BRIEF",
                                 attr_values,
                                 refresh_cache=True,
                                 regex_tag_fill_pattern='^standby-brief\..*')
            if pg_sb.parse():
                result = pg.ext_dictio
                if self.name in result:
                    active_data = result[self.name]
                    if active_data['standby-brief.state'] == 'Standby':
                        break

            time.sleep(sleep_for)
            current_time = time.time()

        end_time = time.time()
        standby_time = end_time - start_time
        LOG.info("Standby sync time = {0}".format(standby_time))

    def wait_for_nats(self, total_expected, max_time=180, sleep_for=5):
        start_time = time.time()
        current_time = time.time()
        timeout = current_time + max_time
        while current_time < timeout:
            attr_values = [('nat-translations.total-key', 'Total'), ]
            pg_nt = pg.oper_fill(
                self.conn,
                "SHOW_IP_NAT_TRANSLATIONS",
                attr_values,
                refresh_cache=True,
                regex_tag_fill_pattern='^nat-translations.total*')
            ## Sridar debug
#            import pdb; pdb.set_trace()
            asr_nats = {}
            if pg_nt.parse():
                result = pg.ext_dictio
                if self.conn.name in result:
                    asr_nats = result[self.conn.name]
                else:
                    msg = "{0} Failed to parse netconf counters".format(
                        self.conn.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            total_nats = asr_nats['nat-translations.total']
            if int(total_nats) >= int(total_expected):
                break

            time.sleep(sleep_for)
            current_time = time.time()

        end_time = time.time()
        nat_time = end_time - start_time
        LOG.info("NAT Translation bring up time = {0}".format(nat_time))

    def verify_vrf(self, rtr, region_id=None):
        vrf_name = "nrouter-" + str(rtr['id'][:6])
        if region_id:
            vrf_name += "-{0}".format(region_id)

        LOG.info("VRF Name = {0}".format(vrf_name))
        time.sleep(60)
        res = pg.oper_fill_tabular(device=self.conn,
                                   show_command="show vrf {0}".format(
                                       vrf_name),
                                   header_fields=["Name", "Default RD",
                                                  "Protocols", "Interfaces"])
        LOG.info("VRF Entries: {0}".format(res))
        entries = res.entries
        if vrf_name not in entries:
            msg = "VRF {0} not found on ASR {1}".format(vrf_name, self.ip)
            raise asr_exceptions.VRFNotConfiguredException(msg)

    def get_netconf_counters(self):
        attr_values = [('netconf-counters.transactions', 'Transactions'), ]
        pg_nc = pg.oper_fill(
            self.conn,
            "SHOW_NETCONF_COUNTERS",
            attr_values,
            refresh_cache=True,
            regex_tag_fill_pattern='^netconf-counters.transaction*')

        netconf_counters = {}
        if pg_nc.parse():
            result = pg.ext_dictio
            if self.conn.name in result:
                netconf_counters = result[self.conn.name]
            else:
                msg = "{0} Failed to parse netconf counters".format(
                    self.conn.name)
                raise asr_exceptions.ShowOutputParserException(msg)
        return netconf_counters

    def wait_for_transactions(self, target, max_time=120, sleep_for=5):
        start_time = time.time()
        current_time = time.time()
        timeout = current_time + max_time
        while current_time < timeout:
            attr_values = [('netconf-counters.transactions', 'Transactions'), ]
            pg_nc = pg.oper_fill(
                self.conn,
                "SHOW_NETCONF_COUNTERS",
                attr_values,
                refresh_cache=True,
                regex_tag_fill_pattern='^netconf-counters.transaction*')

            netconf_counters = {}
            if pg_nc.parse():
                result = pg.ext_dictio
                if self.conn.name in result:
                    netconf_counters = result[self.conn.name]
                else:
                    msg = "{0} Failed to parse netconf counters".format(
                        self.conn.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            if int(netconf_counters['netconf-counters.transactions-total'])\
                    > int(target):
                return current_time - start_time

            time.sleep(sleep_for)
            current_time = time.time()

        msg = "Timeout waiting for netconf transactions on ASR {0}".format(
            self.name)
        raise asr_exceptions.ASRTimeoutException(msg)


class VerifyASRStandby:

    def __init__(self, active, standby):
        self.active = active
        self.standby = standby

    def nat_translations(self, floating_ips):
        total_nats_expected = len(floating_ips)
        self.active.wait_for_nats(total_nats_expected)
        self.standby.wait_for_nats(total_nats_expected)

        for fip_tuple in floating_ips:
            target_ip, server = fip_tuple

            global_ip = target_ip['floating_ip_address']
            local_ip = target_ip['fixed_ip_address']
            for asr in [self.active, self.standby]:
                attr_values = [('nat-translations.inside-global', global_ip), ]
                pg_nt = pg.oper_fill(
                    asr,
                    "SHOW_IP_NAT_TRANSLATIONS",
                    attr_values,
                    refresh_cache=True,
                    regex_tag_fill_pattern='^nat-translations.inside*')

                asr_nats = {}
                if pg_nt.parse():
                    result = pg.ext_dictio
                    if asr.name in result:
                        asr_nats = result[asr.name]
                    else:
                        msg = ("{0} Failed to parse IP NAT Translations "
                               "counters").format(asr.name)
                        raise asr_exceptions.ShowOutputParserException(msg)

                if 'nat-translations.inside-local' not in asr_nats:
                    msg = "No inside local address found for {0}".format(
                        global_ip)
                    raise asr_exceptions.NATNotFoundException(msg)

                if local_ip != asr_nats['nat-translations.inside-local']:
                    key = 'nat-translations.inside-local'
                    msg = ("NAT Mapping for {0} is incorrect:\n "
                           "\tExpected:\t{1}\n \tActual:\t{2}").format(
                        global_ip, local_ip, asr_nats[key])
                    raise asr_exceptions.IncorrectNATMappingException(msg)

    def eot_cfg_sizes(self):
        required_keys = ['test-start', 'test-end']
        active_cfg_sizes = {}
        standby_cfg_sizes = {}

        for key in required_keys:
            try:
                active_cfg_sizes[key] = self.active.get_cfg_size(key)
                standby_cfg_sizes[key] = self.standby.get_cfg_size(key)
            except KeyError:
                LOG.debug("Not enough data in config records to perform test")
                return

        if active_cfg_sizes['test-start'] != active_cfg_sizes['test-end']:
            msg = "Config size difference between start/end: Active ASR"
            return asr_exceptions.ConfigSizeException(msg)

        if standby_cfg_sizes['test-start'] != standby_cfg_sizes['test-end']:
            msg = "Config size difference between start/end: Standby ASR"
            return asr_exceptions.ConfigSizeException(msg)

        if active_cfg_sizes['test-start'] != standby_cfg_sizes['test-start']:
            LOG.debug("Config difference at start of test prevents test")
            return

        if active_cfg_sizes['test-end'] != standby_cfg_sizes['test-end']:
            msg = "Active{0} vs Standby{1} ASR Cfg size mismatch".format(
                active_cfg_sizes['test-end'], standby_cfg_sizes['test-end'])
            raise asr_exceptions.ConfigSizeException(msg)

    def netconf_counters(self):
        for asr in [self.active, self.standby]:
            attr_values = [('netconf-counters.transactions', 'Transactions'), ]
            pg_nc = pg.oper_fill(
                asr,
                "SHOW_NETCONF_COUNTERS",
                attr_values,
                refresh_cache=True,
                regex_tag_fill_pattern='^netconf-counters.transaction*')

            netconf_transactions = {}
            if pg_nc.parse():
                result = pg.ext_dictio
                if asr.name in result:
                    netconf_transactions = result[asr.name]
                else:
                    msg = "{0} Failed to parse netconf counters".format(
                        asr.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            error_key = 'netconf-counters.transaction-errors'
            if int(netconf_transactions[error_key]) != 0:
                msg = "ASR {0} is reporting netconf errors: {1}".format(
                    asr.name, netconf_transactions[error_key])
                # NOTE(bobmel): Too limited error output to act on so just log
                LOG.warn(msg)
                # TODO(sridar): check if netconf counters can be ignored.
                #raise asr_exceptions.NetconfErrorException(msg)

    def swap_asrs(self):
        tmp_asr = self.active
        self.active = self.standby
        self.standby = tmp_asr

    def check_active_asr(self, segment_id):
        intf = self.active.internal_intf_sh + "." + str(segment_id)

        active_data = {}
        for i in range(0, 3):
            attr_values = [('standby-brief.intf', intf), ]
            pg_sb = pg.oper_fill(self.active,
                                 "SHOW_STANDBY_BRIEF",
                                 attr_values,
                                 refresh_cache=True,
                                 regex_tag_fill_pattern='^standby-brief\..*')
#            pdb.set_trace()
            if pg_sb.parse():
                result = pg.ext_dictio
                if self.active.name in result:
                    active_data = result[self.active.name]
                else:
                    msg = ("{0} Failed to parse show standby brief "
                           "output").format(self.active.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            if 'standby-brief.state' in active_data:
                break

            time.sleep(30)

        if active_data['standby-brief.state'] != 'Active':
            tmp_active = self.active
            self.active = self.standby
            self.standby = tmp_active

    def standby_state(self, segment_ids, switch_asr=False,
                      switch_hsrp_priority=False):
        if switch_asr is True:
            tmp_asr = self.active
            self.active = self.standby
            self.standby = tmp_asr

        for id in segment_ids:
            intf = self.active.internal_intf_sh + "." + str(id)
            attr_values = [('standby-brief.intf', intf), ]
            pg_sb = pg.oper_fill(self.active,
                                 "SHOW_STANDBY_BRIEF",
                                 attr_values,
                                 refresh_cache=True,
                                 regex_tag_fill_pattern='^standby-brief\..*')
            active_data = {}
            if pg_sb.parse():
                result = pg.ext_dictio
                if self.active.name in result:
                    active_data = result[self.active.name]
                else:
                    msg = ("{0} Failed to parse show standby brief "
                           "output").format(self.active.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            intf = self.standby.internal_intf_sh + "." + str(id)
            attr_values = [('standby-brief.intf', intf), ]
            pg_sb = pg.oper_fill(self.standby,
                                 "SHOW_STANDBY_BRIEF",
                                 attr_values,
                                 refresh_cache=True,
                                 regex_tag_fill_pattern='^standby-brief\..*')
            standby_data = {}
            if pg_sb.parse():
                result = pg.ext_dictio
                if self.standby.name in result:
                    standby_data = result[self.standby.name]
                else:
                    msg = ("{0} Failed to parse show standby brief "
                           "output").format(self.standby.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            if (int(active_data['standby-brief.group']) !=
                    int(standby_data['standby-brief.group'])):
                msg = ("Active group {0}, Standby group {1}, interface "
                       "{2}").format(active_data['standby-brief.group'],
                                     standby_data['standby-brief.group'])
                raise asr_exceptions.StandbyGroupMismatchException(msg)

            if int(active_data['standby-brief.priority']) < \
                    int(standby_data['standby-brief.priority']):
                msg = ("Active ASR Priority {0} is smaller than "
                       "Standby ASR priority {1} for interface {2}").format(
                        active_data['standby-brief.priority'],
                        standby_data['standby-brief.priority'],
                        intf)
                raise asr_exceptions.StandbyPriorityException(msg)

            if switch_asr is True or switch_hsrp_priority is True:
                if active_data['standby-brief.state'] != 'Standby':
                    msg = ("Active ASR {0} standby state is incorrect for "
                           "interface {1}\n"
                           "\tExpected:\tStandby\n"
                           "\tActual:\t\t{2}").format(
                        self.active.name, intf,
                        active_data['standby-brief.state'])
                    raise asr_exceptions.StandbyStateException(msg)

                if standby_data['standby-brief.state'] != 'Active':
                    msg = ("Standby ASR {0} standby state is incorrect for "
                           "interface {1}\n"
                           "\tExpected:\tActive\n"
                           "\tActual:\t{2}").format(
                        self.standby.name, intf,
                        standby_data['standby-brief.state'])
                    raise asr_exceptions.StandbyStateException(msg)
            else:
                if active_data['standby-brief.state'] != 'Active':
                    msg = ("Active ASR {0} standby state is incorrect for "
                           "interface {1}\n"
                           "\tExpected:\tActive\n"
                           "\tActual:\t\t{2}").format(
                        self.active.name, intf,
                        active_data['standby-brief.state'])
                    raise asr_exceptions.StandbyStateException(msg)

                if standby_data['standby-brief.state'] != 'Standby':
                    msg = ("Standby ASR {0} standby state is incorrect for "
                           "interface {1}\n"
                           "\tExpected:\tStandby\n"
                           "\tActual:\t{2}").format(
                        self.standby.name, intf,
                        standby_data['standby-brief.state'])
                    raise asr_exceptions.StandbyStateException(msg)

            if (active_data['standby-brief.virtual-ip'] !=
                    standby_data['standby-brief.virtual-ip']):
                msg = ("Virtual IP mismatch between Active/Standby ASR for "
                       "interface {0}\n"
                       "Active virtual IP:\t{1}\n"
                       "Standby virtual IP:\t{2}").format(
                    intf, active_data['standby-brief.virtual-ip'],
                    standby_data['standby-brief.virtual-ip'])
                raise asr_exceptions.StandbyVirtualIpException(msg)

    def vrf(self, rtr, rtr_state, region_id=None):
        #pdb.set_trace()
        if rtr_state == 'ACTIVE':
            self.active.verify_vrf(rtr, region_id=region_id)
        if rtr_state == 'STANDBY':
            self.standby.verify_vrf(rtr, region_id=region_id)

    def vrfs(self, routers, tenant_id, region_id=None):
        num_routers = 0
        primary_rtr = {}
        for rtr in routers:
            if rtr['tenant_id'] == tenant_id :
                num_routers += 1
                self.active.verify_vrf(rtr, region_id=region_id)
                primary_rtr = rtr
                break

        primary_rtr_name = str(primary_rtr['name'])
        backup_rtr_name = primary_rtr_name + "_HA_backup_1"
        # Now look for the backup router
        for rtr in routers:
            if rtr['name'] == backup_rtr_name:
                num_routers += 1
                self.standby.verify_vrf(rtr, region_id=region_id)
                break

        if num_routers != 2:
            msg = "Not enough routers found for tenant-id {0}".format(
                tenant_id)
            raise asr_exceptions.NoRedundantASRException(msg)

    def get_rtrs(self, routers_client, tenant_id):
        router_list = routers_client.list_routers()['routers']
        rtrs = {}
        for rtr in router_list:
            if rtr['tenant_id'] == tenant_id:
                rtrs['primary'] = rtr
                break

        backup_rtr_name = rtrs['primary']['name'] + "_HA_backup_1"
        # Now look for the backup router - have to do it by name
        # since tenant ID is not set on backup
        for rtr in router_list:
            if rtr['name'] == backup_rtr_name:
                rtrs['backup'] = rtr
                break

        return rtrs

    def get_backup_rtr(self, target_rtr, routers_client, tenant_id):
        router_list = routers_client.list_routers()['routers']
        rtrs = {}
        for rtr in router_list:
            if (rtr['tenant_id'] == tenant_id and
                    target_rtr['name'] == rtr['name']):
                rtrs['primary'] = rtr
                break

        backup_rtr_name = rtrs['primary']['name'] + "_HA_backup_1"
        # Now look for the backup router - have to do it by name
        # since tenant ID is not set on backup
        for rtr in router_list:
            if rtr['name'] == backup_rtr_name:
                rtrs['backup'] = rtr
                break

        return rtrs

    def get_vrf_name(self, rtr, region_id=None):
        vrf_name = "nrouter-" + rtr['id'][:6]
        if region_id:
            vrf_name += "-{0}".format(region_id)
        return vrf_name

    def nat_pool(self, routers_client, tenant_id, region_id=None):
        routers = self.get_rtrs(routers_client, tenant_id)
        for router_type in ['primary', 'backup']:
            router = routers[router_type]
            vrf_name = self.get_vrf_name(router, region_id=region_id)
            pool_name = vrf_name + "_nat_pool"
            asr = self.standby if router_type == 'backup' else self.active
            attr_values = [('nat-pool.pool-name', pool_name), ]
            pg_sb = pg.oper_fill(asr,
                                 "show ip nat pool name {0}".format(pool_name),
                                 attr_values,
                                 refresh_cache=True,
                                 regex_tag_fill_pattern='^nat-pool\..*')
            nat_pool_data = {}
            if pg_sb.parse():
                result = pg.ext_dictio
                if asr.name in result:
                    nat_pool_data = result[asr.name]
                else:
                    msg = "{0} Failed to parse ip nat pool name output".format(
                        asr.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            if 'nat-pool.pool-name' not in nat_pool_data or \
                            nat_pool_data['nat-pool.pool-name'] != pool_name:
                msg = "NAT Pool {0} is not configured on ASR {1}".format(
                    pool_name, asr.name)
                raise asr_exceptions.NATPoolNotConfiguredException(msg)

            LOG.info("NAT Pool data = {0}".format(nat_pool_data))

    def get_subnets_for_tenant(self, client, tenant_id):
        subnets = client.list_subnets()['subnets']
        tenant_subnets = []
        for subnet in subnets:
            if subnet['tenant_id'] == tenant_id:
                tenant_subnets.append(subnet)
        return tenant_subnets

    def get_network(self, networks_client, id):
        networks = networks_client.list_networks()['networks']
        for network in networks:
            if network['id'] == id:
                return network

    def mk_acl_name(self, port_id, segment_id, region_id=None):
        if region_id is None:
            return "neutron_acl_{0}_{1}".format(segment_id, port_id)
        return "neutron_acl_{0}_{1}_{2}".format(region_id, segment_id, port_id)

    def acls(self, subnets_client, ports_client, networks_client, tenant_id,
             segmentation_ids, region_id=None):

        subnets = self.get_subnets_for_tenant(subnets_client, tenant_id)
        for subnet in subnets:
            LOG.info("Subnet {0}".format(subnet))
            network = self.get_network(networks_client, subnet['network_id'])
            port_list = ports_client.list_ports(
                network_id=subnet['network_id'], status='ACTIVE',
                device_owner='network:router_interface')['ports']
            port_ids = [port['id'] for port in port_list]

            segment_id = network['provider:segmentation_id']
            acl_names = [self.mk_acl_name(port_id[:8], segment_id, region_id)
                         for port_id in port_ids]
            if segment_id not in segmentation_ids:
                msg = ("Network {0} segment_id {1} not in segmentation_ids {2}"
                       " created for this test").format(
                    network['id'], segment_id, segmentation_ids)
                raise asr_exceptions.ASRTestException(msg)

            cidr = subnet['cidr']

            for router_type in ['primary', 'backup']:
                asr = self.active if router_type == 'backup' else self.standby
                for acl_name in acl_names:
                    attr_values = [('acl.name', acl_name), ]
                    pg_acl = pg.oper_fill(asr,
                                          "show access-lists {0}".format(
                                              acl_name),
                                          attr_values,
                                          refresh_cache=True,
                                          regex_tag_fill_pattern='^acl\..*')
                    acl_data = {}
                    if pg_acl.parse():
                        result = pg.ext_dictio
                        if asr.name in result:
                            acl_data = result[asr.name]
                        else:
                            msg = "{0} Failed to parse ACL " \
                                  "output".format(asr.name)
                            raise asr_exceptions.ShowOutputParserException(msg)

                    LOG.info("ACL Data {0}".format(acl_data))

                    if 'acl.name' in acl_data and \
                                    acl_data['acl.name'] == acl_name:
                        break

                if 'acl.name' not in acl_data or \
                            acl_data['acl.name'] != acl_name:
                    msg = "ACL {0} was not found on ASR {1}".format(acl_name,
                                                                    asr.name)
                    raise asr_exceptions.ASRTestException(msg)

                if 'acl.action' not in acl_data or \
                                acl_data['acl.action'] != 'permit':
                    msg = "ACL {0} action {1} is incorrect ".format(
                        acl_name, acl_data['acl.action'])
                    raise asr_exceptions.ASRTestException(msg)

                if 'acl.address' not in acl_data or \
                        not cidr.startswith(acl_data['acl.address']):
                    msg = ("ASL {0} address {1} does not match network "
                           "address {2}").format(
                        acl_name, acl_data['acl.address'], cidr)
                    raise asr_exceptions.ASRTestException(msg)

    def ext_subintf(self, subnets_client, routers_client, networks_client,
                    routers, tenant_id, region_id=None, switch_asr=False):
        routers = self.get_rtrs(routers_client, tenant_id)
        for router_type in ['primary', 'backup']:
            router = routers[router_type]
            vrf_name = self.get_vrf_name(router, region_id=region_id)
            LOG.info("VRF Name {0}".format(vrf_name))
            ext_network_id = router['external_gateway_info']['network_id']
            ext_network = self.get_network(networks_client, ext_network_id)

            # For ASR reboot test, if the active ASR is rebooted, the standby
            # ASR will assume the HSRP active role, and hence the HA state
            # for all the tenant network sub-interfaces will become active.
            # As a result, we need to switch the role of active/standby for
            # both ASRs.
            if switch_asr is True:
                asr = self.standby if router_type == 'primary' else self.active
            else:
                asr = self.standby if router_type == 'backup' else self.active

            attr_values = [('vrf-route.name', vrf_name), ]
            pg_vrf = pg.oper_fill(asr,
                                  "show ip route vrf {0} "
                                  "static".format(vrf_name),
                                  attr_values,
                                  refresh_cache=True,
                                  regex_tag_fill_pattern='^vrf-route\..*')
            vrf_route_data = {}
            if pg_vrf.parse():
                result = pg.ext_dictio
                if asr.name in result:
                    vrf_route_data = result[asr.name]
                else:
                    msg = ("{0} Failed to parse ip route vrf {0} static on "
                          "ASR {1}").format(vrf_name, asr.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            LOG.info("VRF Route data {0}".format(vrf_route_data))

            if 'vrf-route.interface' not in vrf_route_data:
                msg = "No External interface data: ASR {0}".format(asr.name)
                raise asr_exceptions.ASRTestException(msg)

            attr_values = [('sub-intf.name',
                            vrf_route_data['vrf-route.interface'])]
            pg_si = pg.oper_fill(asr,
                                 "show interface {0}".format(
                                     vrf_route_data['vrf-route.interface']),
                                 attr_values,
                                 refresh_cache=True,
                                 regex_tag_fill_pattern='^sub-intf\..*')
            sub_intf_data = {}
            if pg_si.parse():
                result = pg.ext_dictio
                if asr.name in result:
                    sub_intf_data = result[asr.name]
                else:
                    msg = ("{0} Failed to parse interface {0} static on ASR "
                           "{1}").format(vrf_route_data['vrf-route.interface'],
                                         asr.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            subnet_id = ext_network['subnets'][0]
            ext_subnet = subnets_client.show_subnet(subnet_id)['subnet']

            sub_intf_desc = "OPENSTACK_NEUTRON_EXTERNAL_INTF"
            if region_id:
                sub_intf_desc = "OPENSTACK_NEUTRON_{0}_INTF".format(region_id)

            LOG.info("External sub-interface data: {0}".format(sub_intf_data))
            if 'sub-intf.description' not in sub_intf_data or \
                            sub_intf_data['sub-intf.description'] \
                            != sub_intf_desc:
                msg = ("Interface {0} is not the External interface for VRF "
                       "{1} on ASR {2}").format(
                    vrf_route_data['vrf-route.interface'], vrf_name, asr.name)
                raise asr_exceptions.ASRTestException(msg)

            if 'vrf-route.gateway' not in vrf_route_data or \
                            vrf_route_data['vrf-route.gateway'] != \
                            ext_subnet['gateway_ip']:
                msg = ("GW Address not set correctly on External "
                       "subinterface ASR {0}").format(asr.name)
                raise asr_exceptions.ASRTestException(msg)
