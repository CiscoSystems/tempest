#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'nxos': {
        'SHOW_NVE_VNI_COUNTERS': 'show nve vni {} counters',
    },
}
regex = {
    'nxos': {
        #
        # SHOW_NVE_VNI_COUNTERS ('show nve vni {} counters')
        #
        'vni-counters.vni'                : r'VNI:\s+(\d+)',
        'vni-counters.tx'                 : r'(TX)',
        'vni-counters.tx-unicast-pkts'    : r'\s+(\d+) unicast packets\s+\d+ unicast bytes',
        'vni-counters.tx-unicast-bytes'   : r'\s+\d+ unicast packets\s+(\d+) unicast bytes',
        'vni-counters.tx-multicast-pkts'  : r'\s+(\d+) multicast packets\s+\d+ multicast bytes',
        'vni-counters.tx-multicast-bytes' : r'\s+\d+ multicast packets\s+(\d+) multicast bytes',
        'vni-counters.rx'                 : r'(RX)',
        'vni-counters.rx-unicast-pkts'    : r'\s+(\d+) unicast packets\s+\d+ unicast bytes',
        'vni-counters.rx-unicast-bytes'   : r'\s+\d+ unicast packets\s+(\d+) unicast bytes',
        'vni-counters.rx-multicast-pkts'  : r'\s+(\d+) multicast packets\s+\d+ multicast bytes',
        'vni-counters.rx-multicast-bytes' : r'\s+\d+ multicast packets\s+(\d+) multicast bytes',

    },
}
regex_tags = {
    'nxos': [
        #
        # SHOW_NVE_VNI_COUNTERS ('show nve vni {} counters')
        #
        'vni-counters.vni'                ,
        'vni-counters.tx'                 ,
        'vni-counters.tx-unicast-pkts'    ,
        'vni-counters.tx-unicast-bytes'   ,
        'vni-counters.tx-multicast-pkts'  ,
        'vni-counters.tx-multicast-bytes' ,
        'vni-counters.rx'                 ,
        'vni-counters.rx-unicast-pkts'    ,
        'vni-counters.rx-unicast-bytes'   ,
        'vni-counters.rx-multicast-pkts'  ,
        'vni-counters.rx-multicast-bytes' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

