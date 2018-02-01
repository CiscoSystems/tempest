#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'iox': {
        'SHOW_MRIB_ROUTE': 'show mrib route',
    },
    'nxos': {
        'SHOW_MRIB_ROUTE': 'show ip mroute',
    },
}

regex = {
    'iox': {
        #
        # SHOW_MRIB_ROUTE ('show mrib route')
        #
        'mrib-route.source'         : r'\(([A-Fa-f0-9/:\.]+),[A-Fa-f0-9/:\.]+\) RPF nbr:\s+[A-Fa-f0-9:\.]+ Flags:[^\r\n]+',
        'mrib-route.group'          : r'\([A-Fa-f0-9/:\.]+,([A-Fa-f0-9/:\.]+)\) RPF nbr:\s+[A-Fa-f0-9:\.]+ Flags:[^\r\n]+',
        'mrib-route.flags'          : r'\([A-Fa-f0-9/:\.]+,[A-Fa-f0-9/:\.]+\) RPF nbr:\s+[A-Fa-f0-9:\.]+ Flags:([^\r\n]+)',
        'mrib-route.uptime'         : r'\s+Up:\s+(\d{2}:\d{2}:\d{2})',
        'mrib-route.ingress-intf'   : r'\s+([-A-Za-z0-9\._/:]+) Flags:\s+[^,]+, Up:\s+\d{2}:\d{2}:\d{2}',
        'mrib-route.ingress-flags'  : r'\s+[-A-Za-z0-9\._/:]+ Flags:\s+([^,]+), Up:\s+\d{2}:\d{2}:\d{2}',
        'mrib-route.ingress-uptime' : r'\s+[-A-Za-z0-9\._/:]+ Flags:\s+[^,]+, Up:\s+(\d{2}:\d{2}:\d{2})',
        'mrib-route.egress-intf'    : r'\s+([-A-Za-z0-9\._/:]+) Flags:\s+[^,]+, Up:\s+XT<egress-uptime>00:07:16',
        'mrib-route.egress-flags'   : r'\s+[-A-Za-z0-9\._/:]+ Flags:\s+([^,]+), Up:\s+XT<egress-uptime>00:07:16',
    },
    'nxos': {
        #
        # SHOW_MRIB_ROUTE ('show ip mroute')
        #
        'mrib-route.source'        : r'\(([A-Fa-f0-9/:\.]+),\s+[A-Fa-f0-9/:\.]+\)',
        'mrib-route.group'         : r'\([A-Fa-f0-9/:\.]+,\s+([A-Fa-f0-9/:\.]+)\)',
        'mrib-route.uptime'        : r'\([A-Fa-f0-9/:\.]+,\s+[A-Fa-f0-9/:\.]+\), uptime:\s+(\d{2}:\d{2}:\d{2})',
        'mrib-route.protos'        : r'\([A-Fa-f0-9/:\.]+,\s+[A-Fa-f0-9/:\.]+\), uptime:\s+\d{2}:\d{2}:\d{2},\s+([^\r\n]+)',
        'mrib-route.ingress-intf'  : r'\s+Incoming interface:\s+([-A-Za-z0-9\._/:]+), RPF nbr:\s+[A-Fa-f0-9:\.]+',
        'mrib-route.egress-count'  : r'\s+Outgoing interface list:\s+\(count:\s+(\d+)\)',
        'mrib-route.egress-intf'   : r'\s+([-A-Za-z0-9\._/:]+), uptime:\s+\d{2}:\d{2}:\d{2},\s+[^\r\n]+',
        'mrib-route.egress-uptime' : r'\s+[-A-Za-z0-9\._/:]+, uptime:\s+(\d{2}:\d{2}:\d{2}),\s+[^\r\n]+',
        'mrib-route.egress-protos' : r'\s+[-A-Za-z0-9\._/:]+, uptime:\s+\d{2}:\d{2}:\d{2},\s+([^\r\n]+)',
    },
}

