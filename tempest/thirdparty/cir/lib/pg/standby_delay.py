#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_STANDBY_DELAY': 'show standby delay',
    },
}
regex = {
    'ios': {
        #
        # SHOW_STANDBY_DELAY ('show standby delay')
        #
        'standby-delay.intf'   : r'([-A-Za-z0-9\._/:]+)\s+\d+\s+\d+',
        'standby-delay.min'    : r'[-A-Za-z0-9\._/:]+\s+(\d+)\s+\d+',
        'standby-delay.reload' : r'[-A-Za-z0-9\._/:]+\s+\d+\s+(\d+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_STANDBY_DELAY ('show standby delay')
        #
        'standby-delay.intf'   ,
        'standby-delay.min'    ,
        'standby-delay.reload' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

