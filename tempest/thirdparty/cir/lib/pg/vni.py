#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'nxos': {
        'SHOW_VNI': 'show vni',
    },
}
regex = {
    'nxos': {
        #
        # SHOW_VNI ('show vni')
        #
        'vni-table.vni'      : r'(\d+)\s+\w+\s+\d+\s+[-A-Za-z0-9\._/:]+',
        'vni-table.status'   : r'\d+\s+(\w+)\s+\d+\s+[-A-Za-z0-9\._/:]+',
        'vni-table.bd'       : r'\d+\s+\w+\s+(\d+)\s+[-A-Za-z0-9\._/:]+',
        'vni-table.intf'     : r'\d+\s+\w+\s+\d+\s+([-A-Za-z0-9\._/:]+)',
        'vni-table.alt-intf' : r'\s+([-A-Za-z0-9\._/:]+)',

    },
}
regex_tags = {
    'nxos': [
        #
        # SHOW_VNI ('show vni')
        #
        'vni-table.vni'      ,
        'vni-table.status'   ,
        'vni-table.bd'       ,
        'vni-table.intf'     ,
        'vni-table.alt-intf' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)
