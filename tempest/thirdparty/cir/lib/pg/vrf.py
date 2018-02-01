#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'ios': {
        'SHOW_VRF': 'show vrf detail',
    },
}

regex = {
    'ios': {
        #
        # SHOW_VRF ('show vrf detail')
        #
        'vrf.name'       : r'VRF\s+([-A-Za-z0-9\._/:]+) \(VRF Id =\s+[-A-Za-z0-9\._/:]+\); default RD\s+([^;]+); default VPNID\s+([^\n])+',
        'vrf.id'         : r'VRF\s+[-A-Za-z0-9\._/:]+ \(VRF Id =\s+([-A-Za-z0-9\._/:]+)\); default RD\s+([^;]+); default VPNID\s+([^\n])+',
        'vrf.default-rd' : r'VRF\s+[-A-Za-z0-9\._/:]+ \(VRF Id =\s+[-A-Za-z0-9\._/:]+\); default RD\s+(([^;]+)); default VPNID\s+([^\n])+',
        'vrf.default-vpnid' : r'VRF\s+[-A-Za-z0-9\._/:]+ \(VRF Id =\s+[-A-Za-z0-9\._/:]+\); default RD\s+([^;]+); default VPNID\s+(([^\n])+)',
        'vrf.interfaces' : r'\s+(Interfaces):',
        'vrf.intf'       : r'\s+([-A-Za-z0-9\._/:]+)\s+[-A-Za-z0-9\._/:]+\s+[-A-Za-z0-9\._/:]+',
    },
}
