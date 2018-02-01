#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'nxos': {
        'SHOW_INTERFACE': 'show interface | no-more',
    },
}
regex = {
    'nxos': {
        #
        # SHOW_INTERFACE ('show interface | no-more')
        #
        'intf.name'      : r'([-A-Za-z0-9\._/:]+) is\s+\w+',
        'intf.state'     : r'[-A-Za-z0-9\._/:]+ is\s+(\w+)',
        'intf.hardware'  : r'\s+Hardware:\s+(\d+)/\d+ Ethernet, address:\s+[0-9A-Za-z\.\:]+ \(bia\s+[0-9A-Za-z\.\:]+\)',
        'intf.hardware-' : r'\s+Hardware:\s+\d+/(\d+) Ethernet, address:\s+[0-9A-Za-z\.\:]+ \(bia\s+[0-9A-Za-z\.\:]+\)',
        'intf.mac'       : r'\s+Hardware:\s+\d+/\d+ Ethernet, address:\s+([0-9A-Za-z\.\:]+) \(bia\s+[0-9A-Za-z\.\:]+\)',
        'intf.bia'       : r'\s+Hardware:\s+\d+/\d+ Ethernet, address:\s+[0-9A-Za-z\.\:]+ \(bia\s+([0-9A-Za-z\.\:]+)\)',
        'intf.mtu'       : r'\s+MTU\s+(\d+) bytes, BW\s+\d+\s+\w+, DLY\s+\d+\s+\w+',
        'intf.bw'        : r'\s+MTU\s+\d+ bytes, BW\s+(\d+)\s+\w+, DLY\s+\d+\s+\w+',
        'intf.speed'     : r'\s+MTU\s+\d+ bytes, BW\s+\d+\s+(\w+), DLY\s+\d+\s+\w+',
        'intf.delay'     : r'\s+MTU\s+\d+ bytes, BW\s+\d+\s+\w+, DLY\s+(\d+)\s+\w+',
        'intf.time-unit' : r'\s+MTU\s+\d+ bytes, BW\s+\d+\s+\w+, DLY\s+\d+\s+(\w+)',

    },
}
regex_tags = {
    'nxos': [
        #
        # SHOW_INTERFACE ('show interface | no-more')
        #
        'intf.name'      ,
        'intf.state'     ,
        'intf.hardware'  ,
        'intf.hardware-' ,
        'intf.mac'       ,
        'intf.bia'       ,
        'intf.mtu'       ,
        'intf.bw'        ,
        'intf.speed'     ,
        'intf.delay'     ,
        'intf.time-unit' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)


