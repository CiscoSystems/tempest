import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_STANDBY_BRIEF': 'show standby brief',
    },
}
regex = {
    'ios': {
        #
        # SHOW_STANDBY_BRIEF ('show standby brief')
        #
        'standby-brief.intf'       : r'([-A-Za-z0-9\._/:]+)\s+\d+\s+\d+\s+\w+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-f0-9:\.]+',
        'standby-brief.group'      : r'[-A-Za-z0-9\._/:]+\s+(\d+)\s+\d+\s+\w+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-f0-9:\.]+',
        'standby-brief.priority'   : r'[-A-Za-z0-9\._/:]+\s+\d+\s+(\d+)\s+\w+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-f0-9:\.]+',
        'standby-brief.state'      : r'[-A-Za-z0-9\._/:]+\s+\d+\s+\d+\s+(\w+)\s+[A-Fa-o0-9:\.]+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-f0-9:\.]+',
        'standby-brief.active'     : r'[-A-Za-z0-9\._/:]+\s+\d+\s+\d+\s+\w+\s+([A-Fa-o0-9:\.]+)\s+[A-Fa-o0-9:\.]+\s+[A-Fa-f0-9:\.]+',
        'standby-brief.standby'    : r'[-A-Za-z0-9\._/:]+\s+\d+\s+\d+\s+\w+\s+[A-Fa-o0-9:\.]+\s+([A-Fa-o0-9:\.]+)\s+[A-Fa-f0-9:\.]+',
        'standby-brief.virtual-ip' : r'[-A-Za-z0-9\._/:]+\s+\d+\s+\d+\s+\w+\s+[A-Fa-o0-9:\.]+\s+[A-Fa-o0-9:\.]+\s+([A-Fa-f0-9:\.]+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_STANDBY_BRIEF ('show standby brief')
        #
        'standby-brief.intf'       ,
        'standby-brief.group'      ,
        'standby-brief.priority'   ,
        'standby-brief.state'      ,
        'standby-brief.active'     ,
        'standby-brief.standby'    ,
        'standby-brief.virtual-ip' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)


