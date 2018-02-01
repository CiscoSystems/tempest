
import parsercore as pcore

show_commands = {
    'ios': {
        'SHOW_IP_ACCESS_LIST': ' show ip access-lists {}',
    },
}
regex = {
    'ios': {
        #
        # SHOW_IP_ACCESS_LIST (' show ip access-lists {}')
        #
        'acl.name'     : r'Standard IP access list\s+([-A-Za-z0-9\._/:]+)',
        'acl.priorty'  : r'\s+(\d+)\s+\w+\s+[A-Fa-f0-9:\.]+, wildcard bits\s+[A-Fa-f0-9:\.]+',
        'acl.action'   : r'\s+\d+\s+(\w+)\s+[A-Fa-f0-9:\.]+, wildcard bits\s+[A-Fa-f0-9:\.]+',
        'acl.address'  : r'\s+\d+\s+\w+\s+([A-Fa-f0-9:\.]+), wildcard bits\s+[A-Fa-f0-9:\.]+',
        'acl.wildcard' : r'\s+\d+\s+\w+\s+[A-Fa-f0-9:\.]+, wildcard bits\s+([A-Fa-f0-9:\.]+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_IP_ACCESS_LIST (' show ip access-lists {}')
        #
        'acl.name'     ,
        'acl.priorty'  ,
        'acl.action'   ,
        'acl.address'  ,
        'acl.wildcard' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)
