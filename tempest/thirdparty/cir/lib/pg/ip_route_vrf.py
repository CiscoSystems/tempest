import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_IP_VRF_ROUTE': ' show ip vrf {}',
    },
}
regex = {
    'ios': {
        #
        # SHOW_IP_VRF_ROUTE (' show ip vrf {}')
        #
        'vrf-route.name'       : r'Routing Table:\s+([-A-Za-z0-9\._/:]+)',
        'vrf-route.gateway'    : r'Gateway of last resort is\s+([A-Fa-f0-9:\.]+) to network\s+[A-Fa-f0-9:\.]+',
        'vrf-route.gw-network' : r'Gateway of last resort is\s+[A-Fa-f0-9:\.]+ to network\s+([A-Fa-f0-9:\.]+)',
        'vrf-route.code'       : r'(\S+)\s+[A-Fa-f0-9:\.]+/0 \[1/0\] via\s+[A-Fa-f0-9:\.]+,\s+[-A-Za-z0-9\._/:]+',
        'vrf-route.route'      : r'\S+\s+([A-Fa-f0-9:\.]+)/0 \[1/0\] via\s+[A-Fa-f0-9:\.]+,\s+[-A-Za-z0-9\._/:]+',
        'vrf-route.next-hop'   : r'\S+\s+[A-Fa-f0-9:\.]+/0 \[1/0\] via\s+([A-Fa-f0-9:\.]+),\s+[-A-Za-z0-9\._/:]+',
        'vrf-route.interface'  : r'\S+\s+[A-Fa-f0-9:\.]+/0 \[1/0\] via\s+[A-Fa-f0-9:\.]+,\s+([-A-Za-z0-9\._/:]+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_IP_VRF_ROUTE (' show ip vrf {}')
        #
        'vrf-route.name'       ,
        'vrf-route.gateway'    ,
        'vrf-route.gw-network' ,
        'vrf-route.code'       ,
        'vrf-route.route'      ,
        'vrf-route.next-hop'   ,
        'vrf-route.interface'  ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

