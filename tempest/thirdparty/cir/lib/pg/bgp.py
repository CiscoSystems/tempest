#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'iox': {
        'SHOW_BGP_UNICAST_PREFIX': 'show bgp {} unicast {}',
        'SHOW_BGP_NEIGHBOR'      : 'show bgp neighbor {}',
    },
}

regex = {
    'iox': {
        #
        # SHOW_BGP_UNICAST_PREFIX ('show bgp {} unicast {}')
        #
        'bgp-unicast-prefix.prefix'        : r'BGP routing table entry for\s+([A-Fa-f0-9/:\.]+)',
        'bgp-unicast-prefix.num-paths'     : r'Paths:\s+\((\d+) available, best #\d+\)',
        'bgp-unicast-prefix.best-index'    : r'Paths:\s+\(\d+ available, best #(\d+)\)',
        'bgp-unicast-prefix.path'          : r'\s+Path #(\d+):\s+Received by speaker\s+\d+',
        'bgp-unicast-prefix.recv-by'       : r'\s+Path #\d+:\s+Received by speaker\s+(\d+)',
        'bgp-unicast-prefix.origin'        : r'\s+Origin\s+(\w+), metric\s+\d+, localpref\s+\d+',
        'bgp-unicast-prefix.metric'        : r'\s+Origin\s+\w+, metric\s+(\d+), localpref\s+\d+',
        'bgp-unicast-prefix.localpref'     : r'\s+Origin\s+\w+, metric\s+\d+, localpref\s+(\d+)',
        'bgp-unicast-prefix.weight'        : r'\s+Origin\s+\w+, metric\s+\d+, localpref\s+\d+, weight\s+(\d+)',
        'bgp-unicast-prefix.flags'         : r'\s+Origin\s+\w+, metric\s+\d+, localpref\s+\d+, weight\s+\d+,\s+([^\r\n]+)',
        'bgp-unicast-prefix.recv-path-id'  : r'\s+Received Path ID\s+(\d+), Local Path ID\s+\d+, version\s+\d+',
        'bgp-unicast-prefix.local-path-id' : r'\s+Received Path ID\s+\d+, Local Path ID\s+(\d+), version\s+\d+',
        'bgp-unicast-prefix.version'       : r'\s+Received Path ID\s+\d+, Local Path ID\s+\d+, version\s+(\d+)',
        #
        # SHOW_BGP_NEIGHBOR ('show bgp neighbor {}')
        #
        'bgp-nbr.addr'             : r'BGP neighbor is\s+([A-Fa-f0-9:\.]+)',
        'bgp-nbr.remote-as'        : r'\s+Remote AS\s+([-A-Za-z0-9\._/:]+), local AS\s+[-A-Za-z0-9\._/:]+,\s+[^\r\n]+',
        'bgp-nbr.local-as'         : r'\s+Remote AS\s+[-A-Za-z0-9\._/:]+, local AS\s+([-A-Za-z0-9\._/:]+),\s+[^\r\n]+',
        'bgp-nbr.linktype'         : r'\s+Remote AS\s+[-A-Za-z0-9\._/:]+, local AS\s+[-A-Za-z0-9\._/:]+,\s+([^\r\n]+)',
        'bgp-nbr.remote-router-id' : r'\s+Remote router ID\s+([A-Fa-f0-9:\.]+)',
        'bgp-nbr.state'            : r'\s+BGP state =\s+(\w+), up for\s+\d{2}:\d{2}:\d{2}',
        'bgp-nbr.uptime'           : r'\s+BGP state =\s+\w+, up for\s+(\d{2}:\d{2}:\d{2})',
    },
}

