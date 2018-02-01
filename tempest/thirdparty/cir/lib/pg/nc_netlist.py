import parsercore as pcore
show_commands = {
    'linux': {
        'NC_NET_LIST': 'neutron net-list',
    },
}
regex = {
    'linux': {
        #
        # NC_NET_LIST ('neutron net-list')
        #
        'nc_nets.id'          : r'|\s+([-A-Za-z0-9\._/:]+) |\s+[-A-Za-z0-9\._/:]+ |\s+[-A-Za-z0-9\._/:]+\s+[A-Fa-f0-9:\.]+/\d+ |',
        'nc_nets.name'        : r'|\s+[-A-Za-z0-9\._/:]+ |\s+([-A-Za-z0-9\._/:]+) |\s+[-A-Za-z0-9\._/:]+\s+[A-Fa-f0-9:\.]+/\d+ |',
        'nc_nets.subnet-id'   : r'|\s+[-A-Za-z0-9\._/:]+ |\s+[-A-Za-z0-9\._/:]+ |\s+([-A-Za-z0-9\._/:]+)\s+[A-Fa-f0-9:\.]+/\d+ |',
        'nc_nets.subnet'      : r'|\s+[-A-Za-z0-9\._/:]+ |\s+[-A-Za-z0-9\._/:]+ |\s+[-A-Za-z0-9\._/:]+\s+([A-Fa-f0-9:\.]+)/\d+ |',
        'nc_nets.subnet-mask' : r'|\s+[-A-Za-z0-9\._/:]+ |\s+[-A-Za-z0-9\._/:]+ |\s+[-A-Za-z0-9\._/:]+\s+[A-Fa-f0-9:\.]+/(\d+) |',

    },
}
regex_tags = {
    'linux': [
        #
        # NC_NET_LIST ('neutron net-list')
        #
        'nc_nets.id'          ,
        'nc_nets.name'        ,
        'nc_nets.subnet-id'   ,
        'nc_nets.subnet'      ,
        'nc_nets.subnet-mask' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)
