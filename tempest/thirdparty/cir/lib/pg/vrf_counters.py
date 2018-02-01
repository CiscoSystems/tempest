#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'ios': {
        'SHOW_VRF_COUNTERS': 'show vrf counters',
    },
}

regex = {
    'ios': {
        #
        # SHOW_VRF ('show vrf counters')
        #
        'vrf-counters.supported'      : r'Maximum number of VRFs supported:\s+(\d+)',
        'vrf-counters.ipv4-supported' : r'Maximum number of IPv4 VRFs supported:\s+(\d+)',
        'vrf-counters.ipv6-supported' : r'Maximum number of IPv6 VRFs supported:\s+(\d+)',
        'vrf-counters.current'        : r'Current number of VRFs:\s+(\d+)',
        'vrf-counters.ipv4-current'   : r'Current number of IPv4 VRFs:\s+(\d+)',
        'vrf-counters.ipv6-current'   : r'Current number of IPv6 VRFs:\s+(\d+)',
        'vrf-counters.in-delete'      : r'Current number of VRFs in delete state:\s+(\d+)',
    },
}
