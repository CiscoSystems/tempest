import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_IP_SUB_INTERFACE': ' show ip interface {}',
    },
}
regex = {
    'ios': {
        #
        # SHOW_IP_SUB_INTERFACE (' show ip interface {}')
        #
        'sub-intf.name'        : r'([-A-Za-z0-9\._/:]+) is\s+\w+, line protocol is\s+\w+',
        'sub-intf.state'       : r'[-A-Za-z0-9\._/:]+ is\s+(\w+), line protocol is\s+\w+',
        'sub-intf.line-state'  : r'[-A-Za-z0-9\._/:]+ is\s+\w+, line protocol is\s+(\w+)',
        'sub-intf.hardware'    : r'\s+Hardware is\s+([-A-Za-z0-9\._/:]+), address is\s+[0-9A-Za-z\.\:]+ \(bia\s+[0-9A-Za-z\.\:]+\)',
        'sub-intf.mac'         : r'\s+Hardware is\s+[-A-Za-z0-9\._/:]+, address is\s+([0-9A-Za-z\.\:]+) \(bia\s+[0-9A-Za-z\.\:]+\)',
        'sub-intf.bia'         : r'\s+Hardware is\s+[-A-Za-z0-9\._/:]+, address is\s+[0-9A-Za-z\.\:]+ \(bia\s+([0-9A-Za-z\.\:]+)\)',
        'sub-intf.description' : r'\s+Description:\s+(\w+)',
        'sub-intf.address'     : r'\s+Internet address is\s+([A-Fa-f0-9:\.]+)/\d+',
        'sub-intf.mask'        : r'\s+Internet address is\s+[A-Fa-f0-9:\.]+/(\d+)',
        'sub-intf.mtu'         : r'\s+MTU\s+(\d+) bytes, BW\s+\d+\s+[^,]+, DLY\s+\d+\s+\w+,',
        'sub-intf.bw'          : r'\s+MTU\s+\d+ bytes, BW\s+(\d+)\s+[^,]+, DLY\s+\d+\s+\w+,',
        'sub-intf.speed'       : r'\s+MTU\s+\d+ bytes, BW\s+\d+\s+([^,]+), DLY\s+\d+\s+\w+,',
        'sub-intf.delay'       : r'\s+MTU\s+\d+ bytes, BW\s+\d+\s+[^,]+, DLY\s+(\d+)\s+\w+,',
        'sub-intf.delay-units' : r'\s+MTU\s+\d+ bytes, BW\s+\d+\s+[^,]+, DLY\s+\d+\s+(\w+),',
        'sub-intf.encaps'      : r'\s+Encapsulation\s+([^,]+), Vlan ID\s+\d+.',
        'sub-intf.vlan-id'     : r'\s+Encapsulation\s+[^,]+, Vlan ID\s+(\d+).',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_IP_SUB_INTERFACE (' show ip interface {}')
        #
        'sub-intf.name'        ,
        'sub-intf.state'       ,
        'sub-intf.line-state'  ,
        'sub-intf.hardware'    ,
        'sub-intf.mac'         ,
        'sub-intf.bia'         ,
        'sub-intf.description' ,
        'sub-intf.address'     ,
        'sub-intf.mask'        ,
        'sub-intf.mtu'         ,
        'sub-intf.bw'          ,
        'sub-intf.speed'       ,
        'sub-intf.delay'       ,
        'sub-intf.delay-units' ,
        'sub-intf.encaps'      ,
        'sub-intf.vlan-id'     ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)


