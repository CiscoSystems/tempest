#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'nxos': {
        'SHOW_VLAN': 'show vlan brief | no-more',
    },
}
regex = {
    'nxos': {
        #
        # SHOW_VLAN ('show vlan brief | no-more')
        #
        'vlan.id'     : r'(\d+)\s+[a-zA-Z0-9]+[-]\d+\s+\w+\s+(([^,]+),*)+',
        'vlan.name'   : r'\d+\s+([a-zA-Z0-9]+[-]\d+)\s+\w+\s+(([^,]+),*)+',
        'vlan.status' : r'\d+\s+[a-zA-Z0-9]+[-]\d+\s+(\w+)\s+(([^,]+),*)+',
        'vlan.ports'  : r'\d+\s+[a-zA-Z0-9]+[-]\d+\s+\w+\s+((([^,]+),*)+)',

    },
}
regex_tags = {
    'nxos': [
        #
        # SHOW_VLAN ('show vlan brief | no-more')
        #
        'vlan.id'     ,
        'vlan.name'   ,
        'vlan.status' ,
        'vlan.ports'  ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

