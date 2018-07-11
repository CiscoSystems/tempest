"""
**************
devCon
**************

This module implements device connection and control

Author: Kelvin Shum (kfshum@cisco)
"""

try:
    import sys, os
    import pexpect, re, time
    from oslo_log import log as logging
except ImportError as e:
    raise ImportError(e.message)

LOG = logging.getLogger(__name__)


class devCon(pexpect.spawn):
    """
    This class implements a connection session
    """
    basePrompt = re.compile(r'[\w:-~\]\)][\$|#|>|:][\s]*$')
    shPrompt1 = r'[\w:-~\]]\$[\s]*$'
    shPrompt2 = r'[\w:-~\]]>[\s]*$'
    devlog_inst = None
    logger = LOG

    def __init__(self, connectInfo, prompt=None, timeout=10, userName='root',
                 pwTacacs='lab', delay_before_send=0.04, logfile=None,
                 maxread=2000, searchwindowsize=None, devType="calvados",
                 devInfo=None, log_inst=None, **kargs):
        """
        Initialize an object
        """
        if prompt == None:
            self.prompt = devCon.basePrompt
        else:
            self.prompt = prompt

        self.shPrompt1 = devCon.shPrompt1
        self.shPrompt2 = devCon.shPrompt2
        self.timeout = timeout
        self.delaybeforesend = delay_before_send
        self.devType = devType
        self.userName = userName
        self.pwTacacs = pwTacacs
        if logfile == None:
            self.logfile = sys.stdout
        else:
            self.logfile = logfile
        self.maxread = maxread
        self.searchwindowsize = searchwindowsize
        self.connectInfo = connectInfo
        self.timeout = timeout
        self.devInfo = devInfo
        self.errMsgs = []

        ''' Initialization'''
        #if log_inst == None:
        #    self.devlog_inst = logger.Logger("devConsole", "debug", False)
        #    self.logger = self.devlog_inst.get_logger()
        #else:
        #    self.devlog_inst = log_inst
        #    self.logger = log_inst.get_logger()

    def connect(self, timeout=None):
        """
        Connect to device
        """
        self.connected = False
        pexpect.spawn.__init__(self, self.connectInfo, logfile=self.logfile,
                               maxread=self.maxread,
                               searchwindowsize=self.searchwindowsize,
                               timeout=self.timeout)
        try:
            if self.devInfo['searchMsgs']['enable']:
                lines = self.devInfo['searchMsgs']['msgs'].strip()
                self.searchMsgs = lines.split('\n')
            else:
                self.searchMsgs = None
        except (TypeError, KeyError):
            self.searchMsgs = None

        if timeout is None:
            timeout = self.timeout

        self.login(timeout=timeout)
        self.connected = True

    def is_connected(self):
        return self.connected

    def get_os_suffix(self):
        return '-' + self.devType

    def login(self, timeout=None):
        """
        login into device
        """

        if timeout == None:
            timeout = self.timeout

        pl = ['RETURN to get started', 'Escape character is.*\.',
              'not ready for login', '[uU]sername:[\s]*$', '[lL]ogin:[\s]*$',
              '[pP]assword:[\s]*$', 'Permission denied ', '[yY]es',
              self.shPrompt2, self.shPrompt1, self.prompt]
        cpl = self.compile_pattern_list(pl)

        count = 0
        for n in range(10, 0, -1):
            self.logger.debug("Box output: \n%s", self.before)
            count += 1
            try:
                self.sendline('')
                i = self.expect_list(cpl, timeout=timeout)

                if self.searchMsgs != None:
                    ml = [m for m in self.searchMsgs if re.search(re.escape(m),
                                                                  self.before)]
                    if len(ml):
                        self.logger.info("### Found \'{0}\' ###".format(ml))
                        self.errMsgs.extend(ml)
                if i < 2:
                    self.sendline('')
                elif i == 2:
                    tmout = 20*n
                    self.logger.debug("Sleeping {0} seconds".format(
                        str(tmout)))
                    time.sleep(tmout)
                elif (i == 3) or (i == 4):
                    self.sendline(self.userName)
                    j = self.expect(['[pP]assword:[\s]*$', '[sS]ecret:',
                                     'Authentication failed'], timeout=timeout)
                    if j == 0:
                        self.sendline(self.pwTacacs)
                    elif j == 1:
                        self.logger.info("secret is {0}".format(self.pwTacacs))
                        self.sendline(self.pwTacacs)
                        self.expect('[sS]ecret again:', timeout=timeout)
                        self.sendline(self.pwTacacs)
                    else:
                        self.sendline('')
                elif i == 5:
                    self.sendline(self.pwTacacs)
                elif i == 6:
                    r = re.search(r'Offending key in ([^\s]+)', self.before)
                    try:
                        lst = r.group(1).split(":")
                    except:
                        raise Exception("Could not find offending key")
                    ln = str(lst.pop())
                    kh = str(lst.pop())
                    cmd = "sed -i \'{0}d\' {1} > {2}".format(ln, kh, kh)
                    os.system(cmd)
                    pexpect.spawn.__init__(
                        self, self.connectInfo, logfile=self.logfile,
                        maxread=self.maxread,
                        searchwindowsize=self.searchwindowsize)
                elif i == 7:
                    self.sendline('yes')
                elif (i == 8) or (i == 9):
                    if self.devType != "linux":
                        self.sendline('exit')
                    else:
                        self.logger.info("\nLogin to shell OK.")
                        break
                elif i == 10:
                    self.logger.info("\nLogin to shell OK.")
                    break
            except pexpect.EOF:
                raise pexpect.EOF('Connection failed - EOF\n %s ' % str(self))
            except pexpect.TIMEOUT:
                if count < 3:
                    self.sendline('')
                else:
                    raise pexpect.TIMEOUT("Connection timeout\n %s " %
                                          str(self))
            except Exception as e:
                raise Exception("Error {0}".format(e.message))

    def send_command(self, cmd):
        return self.execute_cmd_on_device(cmd)

    def get_os_suffix(self):
        return '-' + self.devType

    def execute(self, cmd, timeout=None, prompt=None, searchwindowsize=None,
                verify=1):
        """
        Execute the command and verify expected prompt
        """

        if prompt is None:
            prompt = self.prompt
        if timeout is None:
            timeout = self.timeout

        if verify is None:
            self.sendline(cmd)
        else:
            try:
                self.send(cmd)
                self.expect_exact(cmd)
            except pexpect.TIMEOUT:
                self.send("\025")
                self.sendline(cmd)
            else:
                self.sendline(' ')

        count = 0
        #self.logger.info("Box output: \n%s", self.before)
        while True:
            count += 1
            try:
                i = self.expect([prompt, '-- MORE --'], timeout=timeout,
                                searchwindowsize=searchwindowsize)
                if self.searchMsgs is not None:
                    ml = [m for m in self.searchMsgs if\
                    re.search(re.escape(m), self.before)]
                    if len(ml):
                        self.logger.info("### Found \'{0}\' ###".format(ml))
                        self.errMsgs.extend(ml)
                if i == 0:
                    break
                elif i == 1:
                    self.send(' ')
            except pexpect.EOF:
                raise pexpect.EOF('command "%s" failed - EOF \n %s ' % (
                    cmd, str(self)))
            except pexpect.TIMEOUT:
                if count < 3:
                    self.sendline(' ')
                    timeout = 5
                else:
                    raise pexpect.TIMEOUT('command "%s" timeout \n %s ' % (
                        cmd, str(self)))
            except Exception as e:
                self.disconnect()
                raise Exception("Error {0}".format(e.message))
        output = str(self.before)
        return output

    def disconnect(self):
        """
        Disconnect from device
        """
        self.logger.info("Disconnecting from device")
        self.close(force=True)

    def sshCopyTo(self, localFile, remotePath):
        """
        ssh scp a file to the device
        """
        print("Not implemented yet")

    def sshCopyFrom(self, remoteHost, remoteFile, localPath, sshPort=None,
                    user="root", passwd="lab"):
        """
        ssh scp a file from the remote host
        """
        print "sshCopyFrom {0} to {1}".format(remoteFile, localPath)
        if not localPath.endswith('/'):
            self.execute("rm -rf %s" % localPath)
            self.execute("touch %s" % localPath)
        while True:
            if sshPort == "None":
                self.sendline('scp {0}@{1}:{2} {3}'.format(
                    user, remoteHost, remoteFile, localPath))
            else:
                self.sendline('scp -P {0} {1}@{2}:{3} {4}'.format(
                    sshPort, user, remoteHost, remoteFile, localPath))
            try:
                i = self.expect([r'[pP]assword:', r'Permission denied',
                                 r'[yY]es'])
                if i == 0:
                    self.execute(passwd, timeout=300)
                    break
                elif i == 1:
                    r = re.search(r'Offending key in ([^\s]+)', self.before)
                    try:
                        lst = r.group(1).split(":")
                    except:
                        raise Exception("Could not find offending key")
                    ln = str(lst.pop())
                    kh = str(lst.pop())
                    cmd = "sed -i \'{0}d\' {1} > {2}".format(ln, kh, kh)
                    os.system(cmd)
                elif i == 2:
                    self.execute(' ')
            except (pexpect.EOF, pexpect.TIMEOUT):
                return False
        return True

    def relogin(self, timeout=30, stateStr='Connection closed', waitTime=20):
        """
        Re-login to a device
        """
        sessionClosed = 0
        try:
            self.execute('', timeout=waitTime, prompt=stateStr, verify=None)
            self.disconnect()
            sessionClosed = 1
        except pexpect.EOF:
            self.disconnect()
            sessionClosed = 1
        except Exception:
            pass

        for n in range(5, 0, -2):
            try:
                if sessionClosed == 1:
                    print "\nRetry connection..."
                    self.connect(timeout=(n*timeout))
                else:
                    print '\nTry re-login...'
                    self.login(timeout=(n*timeout))
                break
            except pexpect.EOF:
                pass
        if n <= 0:
            self.disconnect()
            raise Exception("Error: could not re-login after reload")

    def configure_port_channel_feature(self):
        '''Configures port channel feature on switch'''

        feature_cfg_str = "\n feature lacp \n feature vpc \n"
        self.logger.info("Enable LACP/VPC on the switch %s", feature_cfg_str)
        self.config(feature_cfg_str)
        return

    def reset_switch_port(self, interface_name, intf_type=None):
        """
        Reset interface config
        """

        if intf_type is None:
            reset_cfg_str = "default interface " + str(interface_name) + "\n"
        elif re.match(r'.*peer_link.*|.*ucs_link.*', intf_type):
            interface_name = "port-channel" + str(interface_name)
            reset_cfg_str = "no interface " + str(interface_name) + "\n"
        else:
            reset_cfg_str = ""

        self.logger.info("Restting interface config via: \n %s", reset_cfg_str)
        self.config(reset_cfg_str)
        return 1

    def configure_switch_port(self, vlan_mode, interface_name, vlan_id,
                              speed=0, description="Undefined",
                              nxos_plugin="no", intf_type=None,
                              channel_group=0, split_info=0):
        """
        This function configures a switch in access or trunk mode
        """

        vlan_mode = vlan_mode.strip()
        init_cfg_str = "\n no switchport \n switchport \n"

        if int(speed) != 0:
            init_cfg_str = init_cfg_str + "speed " + str(speed) + "\n"

        if not re.match(r'Undefined', description):
            init_cfg_str = (init_cfg_str + "description via_script " +
                            str(description) + "\n")

        reset_cfg_str = ""

        try:
            if re.match(r'1', split_info) and (intf_type is None):
                skip_intf_reset = 1
            else:
                skip_intf_reset = 0
        except TypeError:
            skip_intf_reset = 0

        if skip_intf_reset:
            vpc_cfg_str = ""
            reset_cfg_str = ""
        elif intf_type is None:
            vpc_cfg_str = ""
            reset_cfg_str = "default interface " + str(interface_name) + "\n"
        elif re.match(r'peer_link', intf_type):
            interface_name = "port-channel" + str(interface_name)
            vpc_cfg_str = ("\n spanning-tree port type network \n vpc "
                           "peer-link \n")
        elif re.match(r'ucs_link', intf_type):
            intf_id = interface_name
            interface_name = "port-channel" + str(interface_name)
            vpc_cfg_str = ("\n spanning-tree port type edge trunk \n shut\n "
                           "no lacp suspend-individual\n vpc " + str(intf_id) +
                           "\n")

        if channel_group:
            channel_grp_str = ("\n channel-group " + str(channel_group) +
                               " mode active")
        else:
            channel_grp_str = ""

        cfg_str = "interface " + str(interface_name) + init_cfg_str

        if re.match(r'no', nxos_plugin) and not re.match(r'all', str(vlan_id)):
            cfg_vlan = "vlan " + str(vlan_id) + "\n no shut \n"
        else:
            cfg_vlan = ""
        cfg_str_add = ""

#        print "VLAN MODE *****" + str(vlan_mode)
        self.logger.debug("VLAN MODE ***** %s", vlan_mode)

        if re.match(r'access', vlan_mode):
            cfg_str_add = "switchport " + vlan_mode + " vlan " + str(vlan_id)
        elif re.match(r'trunk', vlan_mode):
            self.logger.debug("inside VLAN MODE ***** %s", str(vlan_mode))
            if re.match(r'no', nxos_plugin):
                if not channel_group:
                    cfg_str_add = ("switchport mode trunk \n switchport " +
                                   vlan_mode + " allowed vlan " + str(vlan_id))
            else:
                cfg_str_add = ("switchport mode trunk \n switchport " +
                               vlan_mode + " allowed vlan none")

        if len(reset_cfg_str):
            self.logger.info("Restting interface config via: \n %s",
                             reset_cfg_str)
            self.config(reset_cfg_str)

        cfg_2_apply = (cfg_vlan + cfg_str + cfg_str_add + vpc_cfg_str +
                       channel_grp_str + " \n shut \n no shut")

        self.logger.debug("config to apply \n %s", cfg_2_apply)
        #print 'config to apply \n %s'  %(cfg_2_apply)
        self.config(cfg_2_apply)


    def configure_vlan_on_switch(self, vlan_id, ip_address, mask,
                                 action="cfg"):
        """
        This function configures/uncfgs a vlan in a switch
        """

        if re.match(r'cfg', action) and \
            self.is_vlan_configured_on_switch(vlan_id) and \
            not re.match(r'.*all.*|.*none.*', vlan_id):
            print 'Warning Vlan %s is already cfged on the switch, will \
                    overwrite it' % (vlan_id)

        cfg_str = ''
        if re.match(r'cfg', action) and len(ip_address):
            cfg_str = ("feature interface-vlan \n interface vlan " +
                       str(vlan_id) + "\n ip address " + str(ip_address) +
                       "/" + str(mask) + "\n no shut")

        if re.match(r'.*all.*|.*none.*', vlan_id):
            cfg_2_apply = "feature interface-vlan \n"
        elif re.match(r'cfg', action):
            cfg_vlan = ("feature interface-vlan \n no vlan " + str(vlan_id) +
                        "\n vlan " + str(vlan_id) + "\n no shut \n")
            cfg_2_apply = cfg_vlan + cfg_str
        else:
            cfg_2_apply = "no vlan " + str(vlan_id)

        self.logger.debug("VLAN config to apply \n %s", cfg_2_apply)
        self.config(cfg_2_apply)
        return

    def toggle_ports_on_switch(self, interface_list):
        """
        This function toggles the ports on the switch
        """
        for intf in interface_list:
            cmd = "interface " + intf + "\n shut \n no shut \n"
            self.config(cmd)
            time.sleep(5)
        return 1

    def is_vlan_configured_on_switch(self, vlan_id):
        """
        This function checks if vlan is already configured on the switch
        """
        cmd = "show vlan brief | inc " + str(vlan_id)
        self.execute(cmd)
        search_str = "VLAN.*"+str(vlan_id)
        if re.search(search_str, str(self.before)):
            return 1
        else:
            return 0

    def verify_switch_port_config(self, vlan_mode, interface_name, vlan_id,
                                  nxos_plugin="no", channel_group=0):
        """
        This function checks config of a switch port
        """
        cmd = "show run interface " + interface_name
        self.execute(cmd)

        if channel_group and re.match('no', nxos_plugin):
            search_str = "channel-group.*" + str(channel_group)
        elif re.match('no', nxos_plugin):
            search_str = vlan_mode + ".*" + str(vlan_id)
        else:
            search_str = vlan_mode+".*none"
        result = re.search(search_str, str(self.before))
        return result

    def verify_vpc_peer_exists(self, pc_num):
        """
        Verifies if vPC peer exists
        """
        cmd = "show port-channel summary | inc " + str(pc_num)
        self.execute(cmd)

        search_str = "Po" + str(pc_num)
        result1 = re.search(search_str, str(self.before))

        cmd2 = "show vpc brief | inc " + str(pc_num)
        self.execute(cmd2)

        result2 = re.search(search_str, str(self.before))

        if not result2:
            cmd_list = []
            cmd_list.append("show vpc")
            cmd_list.append("show vpc brief")
            cmd_list.append("port-channel summary")
            for cmd in cmd_list:
                self.execute(cmd)

        return result1, result2

    def execute_cmd_on_device(self, cmd):
        """executes a command on device"""
        self.execute(cmd)
        output = str(self.before)
        return output

    def verify_hostname_on_switch(self, expected_switch_name):
        """
        This function checks if the switch hostname is same as expected
        """
        cmd = "show hostname"
        self.execute(cmd)
        search_str = expected_switch_name
        result = re.search(search_str, str(self.before))
        return result


class calCon(devCon):
    """
    This class implements a connection session to calvados
    """

    hostPrompt = r"host:~\]\$ "
    shPrompt = r"sysadmin.*\]\$ "
    def __init__(self, connectInfo, prompt=None, timeout=10, userName='root',
                 pwTacacs='lab', delay_before_send=0.04, logfile=None,
                 maxread=2000, searchwindowsize=None, devType="calvados",
                 **kargs):
        """
        Initialize a calvados object
        """
        devCon.__init__(self, connectInfo, prompt=prompt, timeout=timeout,
                        userName=userName, pwTacacs=pwTacacs,
                        delay_before_send=delay_before_send, logfile=logfile,
                        maxread=maxread, searchwindowsize=searchwindowsize,
                        devType=devType, **kargs)

        self.connect()
        self.hostPrompt = calCon.hostPrompt
        self.shPrompt = calCon.shPrompt
        self.config('no logging console')
        self.execute('show version')
        self.execute('show platform')

    def config(self, cmds, timeout=None, prompt=None, searchwindowsize=None):
        """
        Execute command(s) in config mode
        """
        __config__(self, cmds, timeout=timeout, prompt=prompt,
                   searchwindowsize=searchwindowsize)

    def gotoShell(self):
        """
        Go to calvados shell
        """
        __gotoShell__(self)

    def gotoConsole(self):
        """
        Go to calvados console
        """
        __gotoCon__(self)

    def gotoHost(self):
        """
        Go to host
        """
        __gotoHost__(self)

    def reload(self, location=None, timeout=30):
        """
        Reload hw-module from calvados
        """
        if location == None or location == all:
            location = 'all'
        else:
            location = str(location)
        self.gotoConsole()
        self.execute("hw-module location {0} reload".format(location),
                     prompt=r'Reload hardware module.*yes\]', verify=None)
        self.execute('yes', verify=None)
        self.relogin(timeout=timeout, waitTime=120)

    def relogin(self, timeout=30, waitTime=60):
        """
        Re-login into calvados
        """
        devCon.relogin(self, timeout=timeout, waitTime=waitTime)


class nxosCon(devCon):
    """
    This class implements a connection session to nxos
    """

    def __init__(self, connectInfo, prompt=None, timeout=10, userName='root',
                 pwTacacs='lab', delay_before_send=0.04, logfile=None,
                 maxread=2000, searchwindowsize=None, devType="nxos",
                 machineType="switch", **kargs):
        """
        Initialize a nxos object
        """
        devCon.__init__(self, connectInfo, prompt=prompt, timeout=timeout,
                        userName=userName, pwTacacs=pwTacacs,
                        delay_before_send=delay_before_send, logfile=logfile,
                        maxread=maxread, searchwindowsize=searchwindowsize,
                        devType=devType, machineType=machineType, **kargs)

        self.connect()

        if re.search('switch', machineType):
            self.execute('term length 0')
            self.config("""
                no logging console
                """)

            self.execute('\n')
            self.execute('terminal width 511')
            self.execute('terminal session-timeout 0')
        self.execute('show version')

    def config(self, cmds, timeout=None, prompt=None, searchwindowsize=None):
        """
        Execute command(s) in config mode
        """
        __config__(self, cmds, timeout=timeout, prompt=prompt,
                   searchwindowsize=searchwindowsize)


class xrCon(devCon):
    """
    This class implements a connection session to xr
    """

    hostPrompt = r"host:~\]\$ "
    shPrompt = r"RP.*\]\$ "

    def __init__(self, connectInfo, prompt=None, timeout=10, userName='root',
                 pwTacacs='lab', delay_before_send=0.04, logfile=None,
                 maxread=2000, searchwindowsize=None, devType="xr", **kargs):
        """
        Initialize a xr object
        """
        devCon.__init__(self, connectInfo, prompt=prompt, timeout=timeout,
                        userName=userName, pwTacacs=pwTacacs,
                        delay_before_send=delay_before_send, logfile=logfile,
                        maxread=maxread, searchwindowsize=searchwindowsize,
                        devType=devType, **kargs)

        self.connect()
        self.hostPrompt = xrCon.hostPrompt
        self.shPrompt = xrCon.shPrompt
        self.config("""
            no logging console
            line console
            exec-timeout 0 0
            """)

        self.execute('show version')

    def config(self, cmds, timeout=None, prompt=None, searchwindowsize=None):
        """
        Execute command(s) in config mode
        """
        __config__(self, cmds, timeout=timeout, prompt=prompt,
                   searchwindowsize=searchwindowsize)

    def gotoShell(self):
        """
        Go to xr shell
        """
        __gotoShell__(self)

    def gotoConsole(self):
        """
        Go to xr console
        """
        __gotoCon__(self)

    def gotoHost(self):
        """
        Go to host
        """
        __gotoHost__(self)

    def relogin(self, timeout=120, waitTime=120):
        """
        Re-login to xr
        """
        devCon.relogin(self, timeout=timeout, waitTime=waitTime)


class lnxCon(devCon):
    """
    This class implements a connection session to linux
    """

    def __init__(self, connectInfo, prompt=None, timeout=30, userName='root',
                 pwTacacs='lab', delay_before_send=0.04, logfile=None,
                 maxread=2000,
                 searchwindowsize=None, devType="linux", **kargs):
        """
        Initialize a linux object
        """

        devCon.__init__(self, connectInfo, prompt=prompt, timeout=timeout,
                        userName=userName, pwTacacs=pwTacacs,
                        delay_before_send=delay_before_send, logfile=logfile,
                        maxread=maxread, searchwindowsize=searchwindowsize,
                        devType=devType, **kargs)

        self.connect()
        self.execute('uname -a')
        result = re.search(r"invalid command detected", self.before)
        if result:
            self.execute('connect host', prompt="login:")
            self.relogin(waitTime=5)

    def execute(self, cmd, timeout=None, prompt=None, searchwindowsize=None,
                verify=None):
        """
        Execute the command
        """
        if prompt == None:
            prompt = self.prompt
        if timeout == None:
            timeout = self.timeout
        devCon.execute(self, cmd, timeout, prompt,
                       searchwindowsize=searchwindowsize, verify=verify)

    def disconnect(self):
        """
        Disconnect from linux
        """
        self.sendline('exit')
        devCon.disconnect(self)

    def reload(self, timeout=30):
        """
        Reboot linux
        """
        self.execute('reboot',
                     prompt='The system is going down for reboot NOW!')
        self.relogin(timeout=timeout, waitTime=20)

    reboot = reload


class iosCon(devCon):
    """
    This class implements a connection session to ios
    """

    def __init__(self, connectInfo, prompt=None, timeout=10, userName='root',
                 pwTacacs='lab', delay_before_send=0.04, logfile=None,
                 maxread=2000, searchwindowsize=None, devType="ios",
                 machineType="router", **kargs):
        """
        Initialize a nxos object
        """
        devCon.__init__(self, connectInfo, prompt=prompt,
                        timeout=timeout, userName=userName, pwTacacs=pwTacacs,
                        delay_before_send=delay_before_send, logfile=logfile,
                        maxread=maxread, searchwindowsize=searchwindowsize,
                        devType=devType, machineType=machineType, **kargs)

        self.connect()

        if re.search('router', machineType):
            self.execute('term length 0')
            self.config("""
                no logging console
                """)

            self.execute('\n')
            self.execute('terminal width 511')
            self.execute('terminal length 0')
        self.execute('show version')

    def config(self, cmds, timeout=None, prompt=None, searchwindowsize=None):
        """
        Execute command(s) in config mode
        """
        __config__(self, cmds, timeout=timeout, prompt=prompt,
                   searchwindowsize=searchwindowsize)


### functions ###
def uConsole(connectInfo, prompt=None, timeout=10, userName='root',
             pwTacacs='lab', delay_before_send=0.04, logfile=None,
             maxread=2000, searchwindowsize=None, devType="calvados", **kargs):
    """
    Connect and return an initialized object
    """

    if devType == "calvados":
        print "\nConnecting to calvados\n"
        return calCon(connectInfo, prompt=prompt, timeout=timeout,
                      userName=userName, pwTacacs=pwTacacs,
                      delay_before_send=delay_before_send, logfile=logfile,
                      maxread=maxread, searchwindowsize=searchwindowsize,
                      **kargs)
    elif devType == "xr":
        print "\nConnecting to xr\n"
        return xrCon(connectInfo, prompt=prompt, timeout=timeout,
                     userName=userName, pwTacacs=pwTacacs,
                     delay_before_send=delay_before_send,
                     logfile=logfile, maxread=maxread,
                     searchwindowsize=searchwindowsize, **kargs)
    elif devType == "linux":
        print "\nConnecting to linux/host\n"
        return lnxCon(connectInfo, prompt=prompt, timeout=timeout,
                      userName=userName, pwTacacs=pwTacacs,
                      delay_before_send=delay_before_send,
                      logfile=logfile, maxread=maxread,
                      searchwindowsize=searchwindowsize, **kargs)
    elif devType == "nxos":
        print "\nConnecting to nxos\n"
        return nxosCon(connectInfo, prompt=prompt, timeout=timeout,
                       userName=userName, pwTacacs=pwTacacs,
                       delay_before_send=delay_before_send, logfile=logfile,
                       maxread=maxread, searchwindowsize=searchwindowsize,
                       **kargs)
    elif devType == "ios":
        print "\nConnecting to ios\n"
        return nxosCon(connectInfo, prompt=prompt, timeout=timeout,
                       userName=userName, pwTacacs=pwTacacs,
                       delay_before_send=delay_before_send, logfile=logfile,
                       maxread=maxread, searchwindowsize=searchwindowsize,
                       **kargs)
    else:
        raise TypeError("Invalid device type {0}".format(devType))


def __gotoShell__(uut):
    """
    Go to shell
    """
    try:
        uut.sendline('')
        while True:
            i = uut.expect([uut.hostPrompt, uut.shPrompt, uut.prompt])
            if i == 0:
                uut.sendline('exit')
            elif i == 1:
                break
            elif i == 2:
                uut.sendline('run')
    except pexpect.EOF:
        raise pexpect.EOF('__gotoShell__ failed - EOF \n %s '% (str(uut)))
    except pexpect.TIMEOUT:
        raise pexpect.TIMEOUT('__gotoShell__ timeout\n %s '% (str(uut)))
    except Exception as e:
        uut.disconnect()
        raise Exception("Error {0}".format(e.message))

def __gotoCon__(uut):
    """
    Go to console
    """
    try:
        uut.sendline('')
        while True:
            i = uut.expect([uut.hostPrompt, uut.shPrompt, uut.prompt])
            if i < 2:
                uut.sendline('exit')
            else:
                break
    except pexpect.EOF:
        raise pexpect.EOF('__gotoCon__ failed - EOF \n %s ' % (str(uut)))
    except pexpect.TIMEOUT:
        raise pexpect.TIMEOUT('__gotoCon__ timeout\n %s ' % (str(uut)))
    except Exception as e:
        uut.disconnect()


def __gotoHost__(uut):
    """
    Go to host
    """
    try:
        uut.sendline('')
        while True:
            i = uut.expect([uut.hostPrompt, uut.shPrompt, uut.prompt,
                            "[pP]assword:"])
            if i == 0:
                break
            elif i == 1:
                uut.sendline('chvrf 0 ssh 10.0.2.2')
            elif i == 2:
                uut.sendline('run chvrf 0 ssh 10.0.2.2')
            elif i == 3:
                uut.sendline(uut.pwTacacs)
    except pexpect.EOF:
        raise pexpect.EOF('__gotoHost__ failed - EOF \n %s '% (str(uut)))
    except pexpect.TIMEOUT:
        raise pexpect.TIMEOUT('__gotoHost__ timeout\n %s '% (str(uut)))
    except Exception as e:
        uut.disconnect()
        raise Exception("Error {0}".format(e.message))


def __config__(uut, cmds, timeout=None, prompt=None, searchwindowsize=None):
    """
    Execute command(s) in config mode
    """

    if prompt is None:
        prompt = r'\)#[\s]*$'
    if timeout is None:
        timeout = uut.timeout

    uut.execute('config t', prompt=prompt, timeout=timeout, verify=None)
    for cmd in cmds.split("\n"):
        uut.execute(cmd, prompt=prompt, timeout=timeout, verify=None)
    if uut.devType == "xr":
        uut.execute('commit', prompt=prompt, timeout=timeout, verify=None)
    uut.execute('end')
