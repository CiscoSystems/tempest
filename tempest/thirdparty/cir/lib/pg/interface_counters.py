#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'nxos': {
        'SHOW_INTERFACE_COUNTERS_DETAIL': 'show interface counters detailed | no-more',
    },
}
regex = {
    'nxos': {
        #
        # SHOW_INTERFACE_COUNTERS_DETAIL ('show interface counters detailed | no-more')
        #
        'intf-counters.interface-name'          : r'([-A-Za-z0-9\._/:]+)',
        'intf-counters.rx-total-pkts'           : r'\s+Rx Packets:\s+(\d+)',
        'intf-counters.rx-unicast-pkts'         : r'\s+Rx Unicast Packets:\s+(\d+)',
        'intf-counters.rx-multicast-pkts'       : r'\s+Rx Multicast Packets:\s+(\d+)',
        'intf-counters.rx-broadcast-pkts'       : r'\s+Rx Broadcast Packets:\s+(\d+)',
        'intf-counters.rx-jumbo-pkts'           : r'\s+Rx Jumbo Packets:\s+(\d+)',
        'intf-counters.rx-total-bytes'          : r'\s+Rx Bytes:\s+(\d+)',
        'intf-counters.rx-pkts-0-64-bytes'      : r'\s+Rx Packets from 0 to 64 bytes:\s+(\d+)',
        'intf-counters.rx-pkts-65-127-bytes'    : r'\s+Rx Packets from 65 to 127 bytes:\s+(\d+)',
        'intf-counters.rx-pkts-256-511-bytes'   : r'\s+Rx Packets from 256 to 511 bytes:\s+(\d+)',
        'intf-counters.rx-pkts-512-1023-bytes'  : r'\s+Rx Packets from 512 to 1023 bytes:\s+(\d+)',
        'intf-counters.rx-pkts-1024-1518'       : r'\s+Rx Packets from 1024 to 1518 bytes:\s+(\d+)',
        'intf-counters.tx-total-pkts'           : r'\s+Tx Packets:\s+(\d+)',
        'intf-counters.tx-unicast-pkts'         : r'\s+Tx Unicast Packets:\s+(\d+)',
        'intf-counters.tx-multicast-pkts'       : r'\s+Tx Multicast Packets:\s+(\d+)',
        'intf-counters.tx-broadcast-pkts'       : r'\s+Tx Broadcast Packets:\s+(\d+)',
        'intf-counters.tx-jumbo-pkts'           : r'\s+Tx Jumbo Packets:\s+(\d+)',
        'intf-counters.tx-total-bytes'          : r'\s+Tx Bytes:\s+(\d+)',
        'intf-counters.tx-pkts-0-64-bytes'      : r'\s+Tx Packets from 0 to 64 bytes:\s+(\d+)',
        'intf-counters.tx-pkts-65-127-bytes'    : r'\s+Tx Packets from 65 to 127 bytes:\s+(\d+)',
        'intf-counters.tx-pkts-128-255-bytes'   : r'\s+Tx Packets from 128 to 255 bytes:\s+(\d+)',
        'intf-counters.tx-pkts-256-511-bytes'   : r'\s+Tx Packets from 256 to 511 bytes:\s+(\d+)',
        'intf-counters.tx-pkts-512-1023-bytes'  : r'\s+Tx Packets from 512 to 1023 bytes:\s+(\d+)',
        'intf-counters.tx-pkts-1024-1518-bytes' : r'\s+Tx Packets from 1024 to 1518 bytes:\s+(\d+)',

    },
}
regex_tags = {
    'nxos': [
        #
        # SHOW_INTERFACE_COUNTERS_DETAIL ('show interface counters detailed | no-more')
        #
        'intf-counters.interface-name'          ,
        'intf-counters.rx-total-pkts'           ,
        'intf-counters.rx-unicast-pkts'         ,
        'intf-counters.rx-multicast-pkts'       ,
        'intf-counters.rx-broadcast-pkts'       ,
        'intf-counters.rx-jumbo-pkts'           ,
        'intf-counters.rx-total-bytes'          ,
        'intf-counters.rx-pkts-0-64-bytes'      ,
        'intf-counters.rx-pkts-65-127-bytes'    ,
        'intf-counters.rx-pkts-256-511-bytes'   ,
        'intf-counters.rx-pkts-512-1023-bytes'  ,
        'intf-counters.rx-pkts-1024-1518'       ,
        'intf-counters.tx-total-pkts'           ,
        'intf-counters.tx-unicast-pkts'         ,
        'intf-counters.tx-multicast-pkts'       ,
        'intf-counters.tx-broadcast-pkts'       ,
        'intf-counters.tx-jumbo-pkts'           ,
        'intf-counters.tx-total-bytes'          ,
        'intf-counters.tx-pkts-0-64-bytes'      ,
        'intf-counters.tx-pkts-65-127-bytes'    ,
        'intf-counters.tx-pkts-128-255-bytes'   ,
        'intf-counters.tx-pkts-256-511-bytes'   ,
        'intf-counters.tx-pkts-512-1023-bytes'  ,
        'intf-counters.tx-pkts-1024-1518-bytes' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)


