#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_VLAN_COUNTERS': 'show vlan counters | no-more',
    },
    'nxos': {
        'SHOW_VLAN_COUNTERS': 'show vlan counters | no-more',
    },
}
regex = {
    'ios': {
        #
        # SHOW_VLAN_COUNTERS ('show vlan counters | no-more')
        #
        'vlan-counters.vlan-id'               : r'Vlan Id\s+:(\d+)',
        'vlan-counters.l3-routed-octets-in'   : r'L3 Routed Octets In\s+:(\d+)',
        'vlan-counters.l3-routed-pkts-in'     : r'L3 Routed Packets In\s+:(\d+)',
        'vlan-counters.l3-routed-octets-out'  : r'L3 Routed Octets Out\s+:(\d+)',
        'vlan-counters.l3-routed-pkts-out'    : r'L3 Routed Packets Out\s+:(\d+)',
        'vlan-counters.l3-mcast-octets-in'    : r'L3 Multicast Octets In\s+:(\d+)',
        'vlan-counters.l3-mcast-pkts-in'      : r'L3 Multicast Packets In\s+:(\d+)',
        'vlan-counters.l3-mcast-octets-out'   : r'L3 Multicast Octets Out\s+:(\d+)',
        'vlan-counters.l3-mcast-pkts-out'     : r'L3 Multicast Packets Out\s+:(\d+)',
        'vlan-counters.l3-unicast-octets-in'  : r'L3 Unicast Octets In\s+:(\d+)',
        'vlan-counters.l3-unicast-pkts-in'    : r'L3 Unicast Packets In\s+:(\d+)',
        'vlan-counters.l3-unicast-octets-out' : r'L3 Unicast Octets Out\s+:(\d+)',
        'vlan-counters.l3-unicast-pkts-out'   : r'L3 Unicast Packets Out\s+:(\d+)',
        'vlan-counters.total-octets-in'       : r'Total Octets In\s+:(\d+)',
        'vlan-counters.total-pkts-in'         : r'Total Packets In\s+:(\d+)',
        'vlan-counters.total-octets-out'      : r'Total Octets Out\s+:(\d+)',
        'vlan-counters.total-pkts-out'        : r'Total Packets Out\s+:(\d+)',

    },
    'nxos': {
        #
        # SHOW_VLAN_COUNTERS ('show vlan counters | no-more')
        #
        'vlan-counters.vlan-id'          : r'Vlan Id\s+:(\d+)',
        'vlan-counters.total-octets-in'  : r'Unicast Octets In\s+:(\d+)',
        'vlan-counters.total-pkts-in'    : r'Unicast Packets In\s+:(\d+)',
        'vlan-counters.total-octets-out' : r'Unicast Octets Out\s+:(\d+)',
        'vlan-counters.total-pkts-out'   : r'Unicast Packets Out\s+:(\d+)',

    },

}
regex_tags = {
    'ios': [
        #
        # SHOW_VLAN_COUNTERS ('show vlan counters | no-more')
        #
        'vlan-counters.vlan-id'               ,
        'vlan-counters.l3-routed-octets-in'   ,
        'vlan-counters.l3-routed-pkts-in'     ,
        'vlan-counters.l3-routed-octets-out'  ,
        'vlan-counters.l3-routed-pkts-out'    ,
        'vlan-counters.l3-mcast-octets-in'    ,
        'vlan-counters.l3-mcast-pkts-in'      ,
        'vlan-counters.l3-mcast-octets-out'   ,
        'vlan-counters.l3-mcast-pkts-out'     ,
        'vlan-counters.l3-unicast-octets-in'  ,
        'vlan-counters.l3-unicast-pkts-in'    ,
        'vlan-counters.l3-unicast-octets-out' ,
        'vlan-counters.l3-unicast-pkts-out'   ,
        'vlan-counters.total-octets-in'       ,
        'vlan-counters.total-pkts-in'         ,
        'vlan-counters.total-octets-out'      ,
        'vlan-counters.total-pkts-out'        ,

    ],
    'nxos': [
        #
        # SHOW_VLAN_COUNTERS ('show vlan counters | no-more')
        #
        'vlan-counters.vlan-id'          ,
        'vlan-counters.total-octets-in'  ,
        'vlan-counters.total-pkts-in'    ,
        'vlan-counters.total-octets-out' ,
        'vlan-counters.total-pkts-out'   ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

