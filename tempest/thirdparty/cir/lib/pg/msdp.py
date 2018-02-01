#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'iox': {
        'SHOW_MSDP_PEER': 'show msdp peer',
    },
    'nxos': {
        'SHOW_IP_MSDP_PEER': 'show ip msdp peer',
    },
}

regex = {
    'iox': {
        #
        # SHOW_MSDP_PEER ('show msdp peer')
        #
        'msdp-peer.peer'               : r'MSDP Peer\s+([A-Fa-f0-9:\.]+) \(\?\), AS\s+\d+',
        'msdp-peer.as'                 : r'MSDP Peer\s+[A-Fa-f0-9:\.]+ \(\?\), AS\s+(\d+)',
        'msdp-peer.state'              : r'\s+State:\s+(\w+), Resets:\s+\d+, Connection Source:\s+[A-Fa-f0-9:\.]+',
        'msdp-peer.resets'             : r'\s+State:\s+\w+, Resets:\s+(\d+), Connection Source:\s+[A-Fa-f0-9:\.]+',
        'msdp-peer.connection-source'  : r'\s+State:\s+\w+, Resets:\s+\d+, Connection Source:\s+([A-Fa-f0-9:\.]+)',
        'msdp-peer.uptime'             : r'\s+Uptime\(Downtime\):\s+(\d{2}:\d{2}:\d{2}), SA messages received:\s+0',
        'msdp-peer.password'           : r'\s+Password:\s+([^\r\n]+)',
        'msdp-peer.keepalive-interval' : r'\s+KeepAlive timer period:\s+(\d+)',
        'msdp-peer.keepalive-timeout'  : r'\s+Peer Timeout timer period:\s+(\d+)',
    },
    'nxos': {
        #
        # SHOW_IP_MSDP_PEER ('show ip msdp peer')
        #
        'msdp-peer.peer'                    : r'MSDP peer\s+([A-Fa-f0-9:\.]+) for VRF "[^"]+"',
        'msdp-peer.vrf'                     : r'MSDP peer\s+[A-Fa-f0-9:\.]+ for VRF "([^"]+)"',
        'msdp-peer.as'                      : r'AS\s+(\d+), local address:\s+[A-Fa-f0-9:\.]+',
        'msdp-peer.connection-source'       : r'AS\s+\d+, local address:\s+([A-Fa-f0-9:\.]+)',
        'msdp-peer.description'             : r'\s+Description:\s+([^\r\n]+)',
        'msdp-peer.state'                   : r'\s+Connection status:\s+(\w+)',
        'msdp-peer.uptime'                  : r'\s+Uptime\(Downtime\):\s+(\d{2}:\d{2}:\d{2})',
        'msdp-peer.password'                : r'\s+Password:\s+([^\r\n]+)',
        'msdp-peer.keepalive-interval'      : r'\s+Keepalive Interval:\s+(\d+) sec',
        'msdp-peer.keepalive-timeout'       : r'\s+Keepalive Timeout:\s+(\d+) sec',
        'msdp-peer.rpf-check-failures'      : r'\s+RPF check failures:\s+(\d+)',
        'msdp-peer.established-transitions' : r'\s+Established Transitions:\s+(\d+)',
        'msdp-peer.connection-attempts'     : r'\s+Connection Attempts:\s+(\d+)',
    },
}

