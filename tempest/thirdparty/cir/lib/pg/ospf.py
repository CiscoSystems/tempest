#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'iox': {
        'SHOW_ROUTE'               : 'show route',
        'SHOW_OSPF_NEIGHBOR_DETAIL': 'show ospf neighbor detail',
        'SHOW_OSPF_INTERFACE'      : 'show ospf interface',
    },
    'nxos': {
        'SHOW_IP_OSPF_INTERFACE': 'show ip ospf interface',
    },
}

regex = {
    'iox': {
        #
        # SHOW_ROUTE ('show route')
        #
        'ospf-route.process-id'     : r'Topology Table for ospf\s+(\w+) with ID\s+[A-Fa-f0-9:\.]+',
        'ospf-route.router-id'      : r'Topology Table for ospf\s+\w+ with ID\s+([A-Fa-f0-9:\.]+)',
        'ospf-route.type'           : r'((?:O   |O IA|O E1|O E2|O N1| O N2))\s+[A-Fa-f0-9/:\.]+, metric\s+\d+',
        'ospf-route.unknown-prefix' : r'(?:O   |O IA|O E1|O E2|O N1| O N2)\s+([A-Fa-f0-9/:\.]+), metric\s+\d+',
        'ospf-route.metric'         : r'(?:O   |O IA|O E1|O E2|O N1| O N2)\s+[A-Fa-f0-9/:\.]+, metric\s+(\d+)',
        'ospf-route.\s+('           : r'\s+([A-Fa-f0-9:\.]+),\s+(?:directly connected|from [\d+\.]+), via\s+[-A-Za-z0-9\._/:]+',
        'ospf-route.from'           : r'\s+[A-Fa-f0-9:\.]+,\s+((?:directly connected|from [\d+\.]+)), via\s+[-A-Za-z0-9\._/:]+',
        'ospf-route.via'            : r'\s+[A-Fa-f0-9:\.]+,\s+(?:directly connected|from [\d+\.]+), via\s+([-A-Za-z0-9\._/:]+)',
        #
        # SHOW_OSPF_NEIGHBOR_DETAIL ('show ospf neighbor detail')
        #
        'ospf-nbr.neighbor'                        : r'\s+Neighbor\s+([A-Fa-f0-9:\.]+), interface address\s+[A-Fa-f0-9:\.]+',
        'ospf-nbr.interface-address'               : r'\s+Neighbor\s+[A-Fa-f0-9:\.]+, interface address\s+([A-Fa-f0-9:\.]+)',
        'ospf-nbr.in-the-area'                     : r'\s+In the area\s+(\w+) via interface\s+[-A-Za-z0-9\._/:]+',
        'ospf-nbr.in-the-area-via-interface'       : r'\s+In the area\s+\w+ via interface\s+([-A-Za-z0-9\._/:]+)',
        'ospf-nbr.neighbor-priority'               : r'\s+Neighbor priority is\s+(\d+), State is\s+\w+,\s+\d+ state changes',
        'ospf-nbr.state'                           : r'\s+Neighbor priority is\s+\d+, State is\s+(\w+),\s+\d+ state changes',
        'ospf-nbr.state-changes'                   : r'\s+Neighbor priority is\s+\d+, State is\s+\w+,\s+(\d+) state changes',
        'ospf-nbr.dr'                              : r'\s+DR is\s+([A-Fa-f0-9:\.]+) BDR is\s+[A-Fa-f0-9:\.]+',
        'ospf-nbr.dr-bdr'                          : r'\s+DR is\s+[A-Fa-f0-9:\.]+ BDR is\s+([A-Fa-f0-9:\.]+)',
        'ospf-nbr.options'                         : r'\s+Options is\s+(\w+)',
        'ospf-nbr.lls-options'                     : r'\s+LLS Options is\s+(\w+) \(LR\)',
        'ospf-nbr.dead-timer-due-in'               : r'\s+Dead timer due in\s+(\d{2}:\d{2}:\d{2})',
        'ospf-nbr.neighbor'                        : r'\s+Neighbor is up for\s+(\d{2}:\d{2}:\d{2})',
        'ospf-nbr.dbd-retrans'                     : r'\s+Number of DBD retrans during last exchange\s+(\d+)',
        'ospf-nbr.retransmission-queue-length'     : r'\s+Index 1/1, retransmission queue length\s+(\d+), number of retransmission\s+\d+',
        'ospf-nbr.number-of-retransmission'        : r'\s+Index 1/1, retransmission queue length\s+\d+, number of retransmission\s+(\d+)',
        'ospf-nbr.last-retransmission-scan-length' : r'\s+Last retransmission scan length is\s+(\d+), maximum is\s+\d+',
        'ospf-nbr.maximum'                         : r'\s+Last retransmission scan length is\s+\d+, maximum is\s+(\d+)',
        'ospf-nbr.last-retransmission-scan-time'   : r'\s+Last retransmission scan time is\s+(\d+) msec, maximum is\s+\d+ msec',
        'ospf-nbr.maximum'                         : r'\s+Last retransmission scan time is\s+\d+ msec, maximum is\s+(\d+) msec',
        'ospf-nbr.ls-ack-list:-nsr-sync-pending'   : r'\s+LS Ack list:\s+NSR-sync pending\s+(\d+), high water mark\s+\d+',
        'ospf-nbr.high-water-mark'                 : r'\s+LS Ack list:\s+NSR-sync pending\s+\d+, high water mark\s+(\d+)',
        #
        # SHOW_OSPF_INTERFACE ('show ospf interface')
        #
        'ospf-intf.intf'                        : r'([-A-Za-z0-9\._/:]+) is\s+\w+, line protocol is\s+\w+',
        'ospf-intf.intf-is'                     : r'[-A-Za-z0-9\._/:]+ is\s+(\w+), line protocol is\s+\w+',
        'ospf-intf.line-protocol'               : r'[-A-Za-z0-9\._/:]+ is\s+\w+, line protocol is\s+(\w+)',
        'ospf-intf.internet-address'            : r'\s+Internet Address\s+([A-Fa-f0-9/:\.]+), Area\s+\w+',
        'ospf-intf.area'                        : r'\s+Internet Address\s+[A-Fa-f0-9/:\.]+, Area\s+(\w+)',
        'ospf-intf.process-id'                  : r'\s+Process ID\s+(\w+), Router ID\s+[A-Fa-f0-9:\.]+, Network Type\s+\w+, Cost:\s+\d+',
        'ospf-intf.router-id'                   : r'\s+Process ID\s+\w+, Router ID\s+([A-Fa-f0-9:\.]+), Network Type\s+\w+, Cost:\s+\d+',
        'ospf-intf.network-type'                : r'\s+Process ID\s+\w+, Router ID\s+[A-Fa-f0-9:\.]+, Network Type\s+(\w+), Cost:\s+\d+',
        'ospf-intf.cost'                        : r'\s+Process ID\s+\w+, Router ID\s+[A-Fa-f0-9:\.]+, Network Type\s+\w+, Cost:\s+(\d+)',
        'ospf-intf.transmit-delay'              : r'\s+Transmit Delay is\s+(\d+) sec, State\s+\w+, Priority\s+\d+, MTU\s+\d+, MaxPktSz\s+\d+',
        'ospf-intf.state'                       : r'\s+Transmit Delay is\s+\d+ sec, State\s+(\w+), Priority\s+\d+, MTU\s+\d+, MaxPktSz\s+\d+',
        'ospf-intf.priority'                    : r'\s+Transmit Delay is\s+\d+ sec, State\s+\w+, Priority\s+(\d+), MTU\s+\d+, MaxPktSz\s+\d+',
        'ospf-intf.mtu'                         : r'\s+Transmit Delay is\s+\d+ sec, State\s+\w+, Priority\s+\d+, MTU\s+(\d+), MaxPktSz\s+\d+',
        'ospf-intf.maxpktsz'                    : r'\s+Transmit Delay is\s+\d+ sec, State\s+\w+, Priority\s+\d+, MTU\s+\d+, MaxPktSz\s+(\d+)',
        'ospf-intf.dr'                          : r'\s+Designated Router \(ID\)\s+([A-Fa-f0-9:\.]+), Interface address\s+[A-Fa-f0-9:\.]+',
        'ospf-intf.dr_addr'                     : r'\s+Designated Router \(ID\)\s+[A-Fa-f0-9:\.]+, Interface address\s+([A-Fa-f0-9:\.]+)',
        'ospf-intf.bdr'                         : r'\s+Backup Designated router \(ID\)\s+([A-Fa-f0-9:\.]+), Interface address\s+[A-Fa-f0-9:\.]+',
        'ospf-intf.bdr_addr'                    : r'\s+Backup Designated router \(ID\)\s+[A-Fa-f0-9:\.]+, Interface address\s+([A-Fa-f0-9:\.]+)',
        'ospf-intf.dead_int'                    : r'\s+Timer intervals configured, Hello XNX<hello_int>10, Dead\s+(\d+), Wait\s+\d+, Retransmit\s+\d+',
        'ospf-intf.wait_int'                    : r'\s+Timer intervals configured, Hello XNX<hello_int>10, Dead\s+\d+, Wait\s+(\d+), Retransmit\s+\d+',
        'ospf-intf.retransmit_int'              : r'\s+Timer intervals configured, Hello XNX<hello_int>10, Dead\s+\d+, Wait\s+\d+, Retransmit\s+(\d+)',
        'ospf-intf.hello_due'                   : r'\s+Hello due in\s+(\d{2}:\d{2}:\d{2})',
        'ospf-intf.flood-queue-length'          : r'\s+Index 1/2, flood queue length\s+(\d+)',
        'ospf-intf.last-flood-scan-length'      : r'\s+Last flood scan length is\s+(\d+), maximum is\s+\d+',
        'ospf-intf.maximum'                     : r'\s+Last flood scan length is\s+\d+, maximum is\s+(\d+)',
        'ospf-intf.last-flood-scan-time'        : r'\s+Last flood scan time is\s+(\d+) msec, maximum is\s+\d+ msec',
        'ospf-intf.maximum'                     : r'\s+Last flood scan time is\s+\d+ msec, maximum is\s+(\d+) msec',
        'ospf-intf.ls-ack-list:-current-length' : r'\s+LS Ack List:\s+current length\s+(\d+), high water mark\s+\d+',
        'ospf-intf.high-water-mark'             : r'\s+LS Ack List:\s+current length\s+\d+, high water mark\s+(\d+)',
        'ospf-intf.neighbor-count'              : r'\s+Neighbor Count is\s+(\d+), Adjacent neighbor count is\s+\d+',
        'ospf-intf.adjacent-neighbor-count'     : r'\s+Neighbor Count is\s+\d+, Adjacent neighbor count is\s+(\d+)',
        'ospf-intf.suppress-hello-for'          : r'\s+Suppress hello for\s+(\d+) neighbor\(s\)',
        'ospf-intf.multi-area-interface-count'  : r'\s+Multi-area interface Count is\s+(\d+)',
    },
    'nxos': {
        #
        # SHOW_IP_OSPF_INTERFACE ('show ip ospf interface')
        #
        'ospf-intf.intf'                        : r'([-A-Za-z0-9\._/:]+) is\s+\w+, line protocol is\s+\w+',
        'ospf-intf.intf-is'                     : r'[-A-Za-z0-9\._/:]+ is\s+(\w+), line protocol is\s+\w+',
        'ospf-intf.line-protocol'               : r'[-A-Za-z0-9\._/:]+ is\s+\w+, line protocol is\s+(\w+)',
        'ospf-intf.internet-address'            : r'\s+Internet Address\s+([A-Fa-f0-9/:\.]+), Area\s+\w+',
        'ospf-intf.area'                        : r'\s+Internet Address\s+[A-Fa-f0-9/:\.]+, Area\s+(\w+)',
        'ospf-intf.process-id'                  : r'\s+Process ID\s+(\w+), Router ID\s+[A-Fa-f0-9:\.]+, Network Type\s+\w+, Cost:\s+\d+',
        'ospf-intf.router-id'                   : r'\s+Process ID\s+\w+, Router ID\s+([A-Fa-f0-9:\.]+), Network Type\s+\w+, Cost:\s+\d+',
        'ospf-intf.network-type'                : r'\s+Process ID\s+\w+, Router ID\s+[A-Fa-f0-9:\.]+, Network Type\s+(\w+), Cost:\s+\d+',
        'ospf-intf.cost'                        : r'\s+Process ID\s+\w+, Router ID\s+[A-Fa-f0-9:\.]+, Network Type\s+\w+, Cost:\s+(\d+)',
        'ospf-intf.transmit-delay'              : r'\s+Transmit Delay is\s+(\d+) sec, State\s+\w+, Priority\s+\d+, MTU\s+\d+, MaxPktSz\s+\d+',
        'ospf-intf.state'                       : r'\s+Transmit Delay is\s+\d+ sec, State\s+(\w+), Priority\s+\d+, MTU\s+\d+, MaxPktSz\s+\d+',
        'ospf-intf.priority'                    : r'\s+Transmit Delay is\s+\d+ sec, State\s+\w+, Priority\s+(\d+), MTU\s+\d+, MaxPktSz\s+\d+',
        'ospf-intf.mtu'                         : r'\s+Transmit Delay is\s+\d+ sec, State\s+\w+, Priority\s+\d+, MTU\s+(\d+), MaxPktSz\s+\d+',
        'ospf-intf.maxpktsz'                    : r'\s+Transmit Delay is\s+\d+ sec, State\s+\w+, Priority\s+\d+, MTU\s+\d+, MaxPktSz\s+(\d+)',
        'ospf-intf.dr'                          : r'\s+Designated Router \(ID\)\s+([A-Fa-f0-9:\.]+), Interface address\s+[A-Fa-f0-9:\.]+',
        'ospf-intf.dr_addr'                     : r'\s+Designated Router \(ID\)\s+[A-Fa-f0-9:\.]+, Interface address\s+([A-Fa-f0-9:\.]+)',
        'ospf-intf.bdr'                         : r'\s+Backup Designated router \(ID\)\s+([A-Fa-f0-9:\.]+), Interface address\s+[A-Fa-f0-9:\.]+',
        'ospf-intf.bdr_addr'                    : r'\s+Backup Designated router \(ID\)\s+[A-Fa-f0-9:\.]+, Interface address\s+([A-Fa-f0-9:\.]+)',
        'ospf-intf.dead_int'                    : r'\s+Timer intervals configured, Hello XNX<hello_int>10, Dead\s+(\d+), Wait\s+\d+, Retransmit\s+\d+',
        'ospf-intf.wait_int'                    : r'\s+Timer intervals configured, Hello XNX<hello_int>10, Dead\s+\d+, Wait\s+(\d+), Retransmit\s+\d+',
        'ospf-intf.retransmit_int'              : r'\s+Timer intervals configured, Hello XNX<hello_int>10, Dead\s+\d+, Wait\s+\d+, Retransmit\s+(\d+)',
        'ospf-intf.hello_due'                   : r'\s+Hello due in\s+(\d{2}:\d{2}:\d{2})',
        'ospf-intf.flood-queue-length'          : r'\s+Index 1/2, flood queue length\s+(\d+)',
        'ospf-intf.last-flood-scan-length'      : r'\s+Last flood scan length is\s+(\d+), maximum is\s+\d+',
        'ospf-intf.maximum'                     : r'\s+Last flood scan length is\s+\d+, maximum is\s+(\d+)',
        'ospf-intf.last-flood-scan-time'        : r'\s+Last flood scan time is\s+(\d+) msec, maximum is\s+\d+ msec',
        'ospf-intf.maximum'                     : r'\s+Last flood scan time is\s+\d+ msec, maximum is\s+(\d+) msec',
        'ospf-intf.ls-ack-list:-current-length' : r'\s+LS Ack List:\s+current length\s+(\d+), high water mark\s+\d+',
        'ospf-intf.high-water-mark'             : r'\s+LS Ack List:\s+current length\s+\d+, high water mark\s+(\d+)',
        'ospf-intf.neighbor-count'              : r'\s+Neighbor Count is\s+(\d+), Adjacent neighbor count is\s+\d+',
        'ospf-intf.adjacent-neighbor-count'     : r'\s+Neighbor Count is\s+\d+, Adjacent neighbor count is\s+(\d+)',
        'ospf-intf.suppress-hello-for'          : r'\s+Suppress hello for\s+(\d+) neighbor\(s\)',
        'ospf-intf.multi-area-interface-count'  : r'\s+Multi-area interface Count is\s+(\d+)',
    },
}

