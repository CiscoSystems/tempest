#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'nxos': {
        'SHOW_NVE_VNI': 'show nve vni',
    },
}
regex = {
    'nxos': {
        #
        # SHOW_NVE_VNI ('show nve vni')
        #
        'vni.intf'   : r'([-A-Za-z0-9\._/:]+)\s+\d+\s+[A-Fa-f0-9:\.]+\s+\w+    DP   L2 \[\d+\]',
        'vni.vni'    : r'[-A-Za-z0-9\._/:]+\s+(\d+)\s+[A-Fa-f0-9:\.]+\s+\w+    DP   L2 \[\d+\]',
        'vni.group'  : r'[-A-Za-z0-9\._/:]+\s+\d+\s+([A-Fa-f0-9:\.]+)\s+\w+    DP   L2 \[\d+\]',
        'vni.status' : r'[-A-Za-z0-9\._/:]+\s+\d+\s+[A-Fa-f0-9:\.]+\s+(\w+)    DP   L2 \[\d+\]',
        'vni.bd'     : r'[-A-Za-z0-9\._/:]+\s+\d+\s+[A-Fa-f0-9:\.]+\s+\w+    DP   L2 \[(\d+)\]',

    },
}
regex_tags = {
    'nxos': [
        #
        # SHOW_NVE_VNI ('show nve vni')
        #
        'vni.intf'   ,
        'vni.vni'    ,
        'vni.group'  ,
        'vni.status' ,
        'vni.bd'     ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)
