#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_STANDBY_NBRS': 'show standby neighbors',
    },
}
regex = {
    'ios': {
        #
        # SHOW_STANDBY_NBRS ('show standby neighbors')
        #
        'standby-nbrs.intf'           : r'HSRP neighbors on\s+([-A-Za-z0-9\._/:]+)',
        'standby-nbrs.addr'           : r'\s+([A-Fa-f0-9:\.]+)',
        'standby-nbrs.active-groups'  : r'\s+Active groups:\s+(\d+)',
        'standby-nbrs.standby-groups' : r'\s+Standby groups:\s+(\d+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_STANDBY_NBRS ('show standby neighbors')
        #
        'standby-nbrs.intf'           ,
        'standby-nbrs.addr'           ,
        'standby-nbrs.active-groups'  ,
        'standby-nbrs.standby-groups' ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)
