#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'nxos': {
        'SHOW_IP_PIM_GROUP_RANGE'  : 'show ip pim group-range',
        'SHOW_IP_PIM_INTERFACE'    : 'show ip pim interface',
        'SHOW_IPV6_PIM_GROUP_RANGE': 'show ipv6 pim group-range',
    },
}

regex = {
    'nxos': {
        #
        # SHOW_IP_PIM_GROUP_RANGE ('show ip pim group-range')
        #
        'pim4-group.vrf'     : r'PIM Group-Range Configuration for VRF "([^\"]+)"',
        'pim4-group.group'   : r'([A-Fa-f0-9/:\.]+) \+\S+ \+\S+ \+\S+ \+[^\r\n]+',
        'pim4-group.action'  : r'[A-Fa-f0-9/:\.]+ \+(\S+) \+\S+ \+\S+ \+[^\r\n]+',
        'pim4-group.mode'    : r'[A-Fa-f0-9/:\.]+ \+\S+ \+(\S+) \+\S+ \+[^\r\n]+',
        'pim4-group.rp'      : r'[A-Fa-f0-9/:\.]+ \+\S+ \+\S+ \+(\S+) \+[^\r\n]+',
        'pim4-group.strange' : r'[A-Fa-f0-9/:\.]+ \+\S+ \+\S+ \+\S+ \+([^\r\n]+)',
        #
        # SHOW_IP_PIM_INTERFACE ('show ip pim interface')
        #
        'pim-intf.intf'                            : r'([-A-Za-z0-9\._/:]+), Interface status:\s+[^/]+/[^/]+/[^\r\n]+',
        'pim-intf.proto_status'                    : r'[-A-Za-z0-9\._/:]+, Interface status:\s+([^/]+)/[^/]+/[^\r\n]+',
        'pim-intf.link_status'                     : r'[-A-Za-z0-9\._/:]+, Interface status:\s+[^/]+/([^/]+)/[^\r\n]+',
        'pim-intf.config_status'                   : r'[-A-Za-z0-9\._/:]+, Interface status:\s+[^/]+/[^/]+/([^\r\n]+)',
        'pim-intf.dr_addr'                         : r'\s+PIM DR:\s+([A-Fa-f0-9:\.]+), DR\'s priority:\s+\d+',
        'pim-intf.dr_pri'                          : r'\s+PIM DR:\s+[A-Fa-f0-9:\.]+, DR\'s priority:\s+(\d+)',
        'pim-intf.nbr_count'                       : r'\s+PIM neighbor count:\s+(\d+)',
        'pim-intf.hello_int'                       : r'\s+PIM hello interval:\s+(\d+) secs, next hello sent in:\s+\d{2}:\d{2}:\d{2}',
        'pim-intf.next_hello'                      : r'\s+PIM hello interval:\s+\d+ secs, next hello sent in:\s+(\d{2}:\d{2}:\d{2})',
        'pim-intf.nbr_hold'                        : r'\s+PIM neighbor holdtime:\s+(\d+) secs',
        'pim-intf.config_dr_pri'                   : r'\s+PIM configured DR priority:\s+(\d+)',
        'pim-intf.pim-border-interface'            : r'\s+PIM border interface:\s+(\w+)',
        'pim-intf.pim-hello-md5-ah-authentication' : r'\s+PIM Hello MD5-AH Authentication:\s+(\w+)',
        'pim-intf.pim-neighbor-policy'             : r'\s+PIM Neighbor policy:\s+([^\r\n]+)',
        'pim-intf.pim-join-prune-inbound-policy'   : r'\s+PIM Join-Prune inbound policy:\s+([^\r\n]+)',
        'pim-intf.pim-join-prune-outbound-policy'  : r'\s+PIM Join-Prune outbound policy:\s+([^\r\n]+)',
        'pim-intf.pim-join-prune-interval'         : r'\s+PIM Join-Prune interval:\s+([^\r\n]+)',
        'pim-intf.pim-join-prune-next-sending'     : r'\s+PIM Join-Prune next sending:\s+([^\r\n]+)',
        'pim-intf.pim-bfd-enabled'                 : r'\s+PIM BFD enabled:\s+([^\r\n]+)',
        'pim-intf.pim-passive-interface'           : r'\s+PIM passive interface:\s+([^\r\n]+)',
        'pim-intf.pim-vpc-svi'                     : r'\s+PIM VPC SVI:\s+([^\r\n]+)',
        #
        # SHOW_IPV6_PIM_GROUP_RANGE ('show ipv6 pim group-range')
        #
        'pim6-group.vrf'     : r'PIM6 Group-Range Configuration for VRF "([^\"]+)"',
        'pim6-group.group'   : r'([A-Fa-f0-9/:\.]+) \+\S+ \+\S+ \+[^\r\n]+',
        'pim6-group.mode'    : r'[A-Fa-f0-9/:\.]+ \+(\S+) \+\S+ \+[^\r\n]+',
        'pim6-group.rp'      : r'[A-Fa-f0-9/:\.]+ \+\S+ \+(\S+) \+[^\r\n]+',
        'pim6-group.strange' : r'[A-Fa-f0-9/:\.]+ \+\S+ \+\S+ \+([^\r\n]+)',
    },
}

