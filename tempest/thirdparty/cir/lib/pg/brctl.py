#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'nxos': {
        'SHOW_BRIDGE': 'brctl show\n',
    },
}

regex = {
    'nxos': {
        #
        # SHOW_BRIDGE ('brctl show')
        #
        'bridge.name'      : r'(brq[-A-Za-z0-9\._/:]+)\s+[-A-Za-z0-9\._/:]+\s+\w+\s+tap[-A-Za-z0-9\._/:]+',
        'bridge.id'        : r'brq[-A-Za-z0-9\._/:]+\s+([-A-Za-z0-9\._/:]+)\s+\w+\s+tap[-A-Za-z0-9\._/:]+',
        'bridge.stp'       : r'brq[-A-Za-z0-9\._/:]+\s+[-A-Za-z0-9\._/:]+\s+(\w+)\s+tap[-A-Za-z0-9\._/:]+',
        'bridge.tap'      : r'brq[-A-Za-z0-9\._/:]+\s+[-A-Za-z0-9\._/:]+\s+\w+\s+(tap[-A-Za-z0-9\._/:]+)',
        'bridge.interface' : r'\s+((vlan|vxlan)[-A-Za-z0-9\._/:]+)',
    },
}
