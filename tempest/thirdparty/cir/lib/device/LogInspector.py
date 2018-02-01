import datetime
import os
import pprint
import re
import ast

from oslo_log import log as logging
from collections import OrderedDict


LOG = logging.getLogger(__name__)

class LogError():

    def __init__(self, date, time, id, err_str):
        self.date = date
        self.time = time
        self.id = id
        self.err_str = err_str

class LogInspectorException(Exception):

    def __init__(self, message):
        super(LogInspectorException, self).__init__(message)


class LogInspector:

    def __init__(self, log_dir=''):

        # Determine RH or Devstack by location of logs
        if log_dir != '':
            self.log_dir = log_dir
            self.logs = ['cisco-cfg-agent.log']
            self.cfg_agent_log = 'cisco-cfg-agent.log'
        else:

            test_log_file = '/var/log/neutron/server.log'
            if os.path.isfile(test_log_file):
                # RH
                self.log_dir = '/var/log/neutron'
                self.logs = ['server.log',
                             'cisco-cfg-agent.log',
                             'dhcp-agent.log',
                             'l3-agent.log']
                self.cfg_agent_log = 'cisco-cfg-agent.log'
            elif os.path.isfile('/opt/stack/logs/q-ciscocfgagent.log'):
                # Devstack
                self.log_dir = '/opt/stack/logs'
                self.logs = ['q-ciscocfgagent.log',
                             'q-svc.log']
                self.cfg_agent_log = 'q-ciscocfgagent.log'

        # Refine the list of logs
        potential_logs = self.logs
        for log in potential_logs:
            full_log_fn = self.log_dir + "/" + log
            if not os.path.isfile(full_log_fn):
                self.logs.remove(log)

        self.re_error_exception_list = []
        self.re_trace_exception_list = []
        self.log_error_re =\
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sERROR.+')
        self.log_traceback_re = \
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sTRACE.+')
        # Expected Trace for connection failure when the ASR management interface is disabled
        # DE1164
        self.log_connect_trace_re = \
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sTRACE.+plugins.cisco.cfg_agent'
                       r'.service_helpers.routing_svc_helper.+')
        self.re_trace_exception_list.append(self.log_connect_trace_re)
        # Expected error for ping failure when the ASR management interface is disabled
        self.log_ping_fail_re = \
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sERROR.+agent.linux.utils.+')
        self.re_error_exception_list.append(self.log_ping_fail_re)

        # Expected error for Rabbit MQ on container swo
        self.rabbit_conn_err = \
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sERROR.+oslo.messaging._drivers.impl_rabbit.+AMQP.server.on.+is.unreachable.+Too.many.heartbeats.missed.*')
        self.re_error_exception_list.append(self.rabbit_conn_err)

        # Expected error for connection failure when the ASR management interface is disabled
        # DE1164)
        self.log_connect_error_re = \
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sERROR.+plugins.cisco.cfg_agent'
                       r'.service_helpers.routing_svc_helper.+')
        self.re_error_exception_list.append(self.log_connect_error_re)
        # Expected error in DE1897
        self.log_dhcp_api_error_re = \
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sERROR.+api.rpc.agentnotifiers.dhcp_rpc_agent_api.+')
        self.re_error_exception_list.append(self.log_dhcp_api_error_re)

        self.ext_paths_dont_exist_error_re = re.compile(r'([\d-]+)\s+([0-9:\.]+)\sERROR.+neutron.api.extensions.+')
        self.re_error_exception_list.append(self.ext_paths_dont_exist_error_re)

        self.state_report_start_re = \
            re.compile(r'([\d-]+)\s+([0-9:\.]+)\sDEBUG.+plugins.cisco.cfg_agent.cfg_agent.+State report.+')
        self.state_report_end_re = re.compile(r'.+_report_state.+')
        self.state_report_re = re.compile(r'.+State report: ({.+}).+_report_state.+')

        self.ansi_escape = re.compile(r'\x1b[^m]*m')

        self.date_format = "%Y-%m-%d %H:%M:%S.%f"
        self.log_errors = {}
        self.state_reports = OrderedDict()
        self.record_errors('baseline')
        self.reference_time = datetime.datetime

    def record_errors(self, id):
        for log in self.logs:
            log_file = self.log_dir + "/" + log
            if os.path.isfile(log_file):
                log_content = [line.rstrip('\n') for line in open(log_file)]
                self.find_errors(id, log_file, log_content)

    def find_errors(self, id, log_file, content):
        errors = []
        tracebacks = []
        for line in content:
            line = self.ansi_escape.sub('', line)
            if self.log_error_re.match(line):
                exceptions = [True for x in self.re_error_exception_list if x.match(line)]
                if len(exceptions) == 0:
                    errors.append(line)
            if self.log_traceback_re.match(line):
                exceptions = [True for x in self.re_trace_exception_list if x.match(line)]
                if len(exceptions) == 0:
                    tracebacks.append(line)
        total_errors = len(errors)
        total_tracebacks = len(tracebacks)
        log = os.path.basename(log_file)
        if self.log_errors.has_key(id) is False:
            self.log_errors[id] = {}

        self.log_errors[id][log] = {'errors': total_errors,
                                    'tracebacks': total_tracebacks}

    def find_state_reports(self):
        log_file = self.log_dir + "/" + self.cfg_agent_log

        sr_flag = False
        for line in open(log_file):
            line = self.ansi_escape.sub('', line)
            if self.state_report_start_re.match(line.rstrip('\r\n')):
                m = self.state_report_start_re.match(line.rstrip('\r\n'))
                sr_key = m.group(1) + " " + m.group(2)
                state_report = ""
                sr_flag = True

            if sr_flag and self.state_report_end_re.match(line.rstrip('\r\n')):
                state_report += line.rstrip('\r\n')
                m = self.state_report_re.match(state_report)
                if m and sr_key not in self.state_reports:
                    self.state_reports[sr_key] = ast.literal_eval(m.group(1))
                sr_flag = False

            if sr_flag:
                state_report += line.rstrip('\r\n')

    def get_state_reports(self, after):
        self.find_state_reports()

        rdict = OrderedDict()
        for k, v in self.state_reports.items():
            timestamp = datetime.datetime.strptime(k, self.date_format)
            if timestamp > after:
                rdict[k] = v

        return rdict

    def get_fault_report(self, log, type, id):
        log_file = self.log_dir + "/" + log
        if os.path.isfile(log_file):
            log_content = [line.rstrip('\n') for line in open(log_file)]

        current_error_id = 0
        current_tb_id = 0
        id += 1
        return_str = "\n"
        for line in log_content:
            line = self.ansi_escape.sub('', line)
            if self.log_error_re.match(line):
                current_error_id += 1
            if self.log_traceback_re.match(line):
                current_tb_id += 1

            if type is 'ERROR' and current_error_id >= id:
                if self.log_error_re.match(line) or \
                        self.log_traceback_re.match(line):
                    if not self.log_ping_fail_re.match(line):
                        return_str += line + "\n"
            if type is 'TRACEBACK' and current_error_id >= id:
                if self.log_error_re.match(line) or \
                        self.log_traceback_re.match(line):
                    if not self.log_ping_fail_re.match(line):
                        return_str += line + "\n"

        return return_str

    def show_log_errors(self):
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(self.log_errors)

    def compare_logs(self, id1, id2):
        logs1 = self.log_errors[id1]
        logs2 = self.log_errors[id2]

        for log in self.logs:
            if logs2[log]['tracebacks'] > logs1[log]['tracebacks']:
                diff = int(logs2[log]['tracebacks']) - \
                       int(logs1[log]['tracebacks'])
                msg = "{0} new Tracebacks found in log {1}".format(diff, log)
                msg += self.get_fault_report(log, 'TRACEBACK',
                                             logs1[log]['errors'])
                raise LogInspectorException(msg)

            if logs2[log]['errors'] > logs1[log]['errors']:
                diff = int(logs2[log]['errors']) - \
                       int(logs1[log]['errors'])
                msg = "{0} new ERRORS found in log {1}".format(diff, log)
                msg += self.get_fault_report(log, 'ERROR',
                                             logs1[log]['errors'])
                raise LogInspectorException(msg)


