#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_STANDBY_REDIRECT': 'show standby redirect',
    },
}
regex = {
    'ios': {
        #
        # SHOW_STANDBY_REDIRECT ('show standby redirect')
        #
        'standby-redirect.intf'        : r'([-A-Za-z0-9\._/:]+)\s+\w+\s+\w+\s+\d+\s+\d+',
        'standby-redirect.redirect'    : r'[-A-Za-z0-9\._/:]+\s+(\w+)\s+\w+\s+\d+\s+\d+',
        'standby-redirect.unknown'     : r'[-A-Za-z0-9\._/:]+\s+\w+\s+(\w+)\s+\d+\s+\d+',
        'standby-redirect.adv'         : r'[-A-Za-z0-9\._/:]+\s+\w+\s+\w+\s+(\d+)\s+\d+',
        'standby-redirect.holddown'    : r'[-A-Za-z0-9\._/:]+\s+\w+\s+\w+\s+\d+\s+(\d+)',
        'standby-redirect.addr'        : r'(\S+)\s+\d+\s+[-A-Za-z0-9\._/:]+',
        'standby-redirect.hits'        : r'\S+\s+(\d+)\s+[-A-Za-z0-9\._/:]+',
        'standby-redirect.active-intf' : r'\S+\s+\d+\s+([-A-Za-z0-9\._/:]+)',
        'standby-redirect.group'       : r'\s+(\d+)\s+[A-Fa-f0-9:\.]+\s+[0-9A-Za-z\.\:]+',
        'standby-redirect.vaddr'       : r'\s+\d+\s+([A-Fa-f0-9:\.]+)\s+[0-9A-Za-z\.\:]+',
        'standby-redirect.vmac'        : r'\s+\d+\s+[A-Fa-f0-9:\.]+\s+([0-9A-Za-z\.\:]+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_STANDBY_REDIRECT ('show standby redirect')
        #
        'standby-redirect.intf'        ,
        'standby-redirect.redirect'    ,
        'standby-redirect.unknown'     ,
        'standby-redirect.adv'         ,
        'standby-redirect.holddown'    ,
        'standby-redirect.addr'        ,
        'standby-redirect.hits'        ,
        'standby-redirect.active-intf' ,
        'standby-redirect.group'       ,
        'standby-redirect.vaddr'       ,
        'standby-redirect.vmac'        ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

