#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_IP_NAT_POOL': ' show ip nat pool name {}',
    },
}
regex = {
    'ios': {
        #
        # SHOW_IP_NAT_POOL (' show ip nat pool name {}')
        #
        'nat-pool.pool-name'           : r'Pool name\s+([-A-Za-z0-9\._/:]+), id\s+\d+',
        'nat-pool.id'                  : r'Pool name\s+[-A-Za-z0-9\._/:]+, id\s+(\d+)',
        'nat-pool.assigned-addresses'  : r'\s+Addresses\s+(\d+)\s+\d+',
        'nat-pool.available-addresses' : r'\s+Addresses\s+\d+\s+(\d+)',
        'nat-pool.assigned-low-udp'    : r'\s+UDP Low Ports\s+(\d+)\s+\d+',
        'nat-pool.available-low-udp'   : r'\s+UDP Low Ports\s+\d+\s+(\d+)',
        'nat-pool.assigned-low-tcp'    : r'\s+TCP Low Ports\s+(\d+)\s+\d+',
        'nat-pool.available-low-tcp'   : r'\s+TCP Low Ports\s+\d+\s+(\d+)',
        'nat-pool.assigned-high-udp'   : r'\s+UDP High Ports\s+(\d+)\s+\d+',
        'nat-pool.available-high-udp'  : r'\s+UDP High Ports\s+\d+\s+(\d+)',
        'nat-pool.assigned-high-tcp'   : r'\s+TCP High Ports\s+(\d+)\s+\d+',
        'nat-pool.available-high-tcp'  : r'\s+TCP High Ports\s+\d+\s+(\d+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_IP_NAT_POOL (' show ip nat pool name {}')
        #
        'nat-pool.pool-name'           ,
        'nat-pool.id'                  ,
        'nat-pool.assigned-addresses'  ,
        'nat-pool.available-addresses' ,
        'nat-pool.assigned-low-udp'    ,
        'nat-pool.available-low-udp'   ,
        'nat-pool.assigned-low-tcp'    ,
        'nat-pool.available-low-tcp'   ,
        'nat-pool.assigned-high-udp'   ,
        'nat-pool.available-high-udp'  ,
        'nat-pool.assigned-high-tcp'   ,
        'nat-pool.available-high-tcp'  ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)


