#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_STANDBY_INTERFACE': 'show standby',
    },
}
regex = {
    'ios': {
        #
        # SHOW_STANDBY_INTERFACE ('show standby')
        #
        'standby-intf.intf'                                : r'([-A-Za-z0-9\._/:]+) - Group\s+\d+ \(version\s+\d+\)',
        'standby-intf.group'                               : r'[-A-Za-z0-9\._/:]+ - Group\s+(\d+) \(version\s+\d+\)',
        'standby-intf.version'                             : r'[-A-Za-z0-9\._/:]+ - Group\s+\d+ \(version\s+(\d+)\)',
        'standby-intf.state'                               : r'\s+State is\s+(\w+)',
        'standby-intf.state-change'                        : r'\s+(\d+) state change, last state change\s+\d{2}:\d{2}:\d{2}',
        'standby-intf.last-change'                         : r'\s+\d+ state change, last state change\s+(\d{2}:\d{2}:\d{2})',
        'standby-intf.vaddr'                               : r'\s+Virtual IP address is\s+([A-Fa-f0-9:\.]+)',
        'standby-intf.active-vmac'                         : r'\s+Active virtual MAC address is\s+([0-9A-Za-z\.\:]+)\s+.*',
        'standby-intf.active-virtual-mac-address-unknown'  : r'\s+Active virtual MAC address is\s+[0-9A-Za-z\.\:]+\s+(.*)',
        'standby-intf.localc-mac'                          : r'\s+Local virtual MAC address is\s+([0-9A-Za-z\.\:]+)\s+.*',
        'standby-intf.local-virtual-mac-address-unknown'   : r'\s+Local virtual MAC address is\s+[0-9A-Za-z\.\:]+\s+(.*)',
        'standby-intf.hello-time'                          : r'\s+Hello time\s+(\d+) sec, hold time\s+\d+ sec',
        'standby-intf.hold-time'                           : r'\s+Hello time\s+\d+ sec, hold time\s+(\d+) sec',
        'standby-intf.preemption'                          : r'\s+Preemption\s+(\w+)',
        'standby-intf.active-rtr-ip'                       : r'\s+Active router is\s+([A-Fa-f0-9:\.]+), priority\s+\d+\s+.*',
        'standby-intf.active-rtr-priority'                 : r'\s+Active router is\s+[A-Fa-f0-9:\.]+, priority\s+(\d+)\s+.*',
        'standby-intf.active-router-active-router-unknown' : r'\s+Active router is\s+[A-Fa-f0-9:\.]+, priority\s+\d+\s+(.*)',
        'standby-intf.active-rtr-mac'                      : r'\s+MAC address is\s+([0-9A-Za-z\.\:]+)',
        'standby-intf.standby-rtr'                         : r'\s+Standby router is\s+(\S+)',
        'standby-intf.priority'                            : r'\s+Priority\s+(\d+) \(configured\s+\d+\)',
        'standby-intf.configured-priority'                 : r'\s+Priority\s+\d+ \(configured\s+(\d+)\)',
        'standby-intf.group-name'                          : r'\s+Group name is "([^\"].+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_STANDBY_INTERFACE ('show standby')
        #
        'standby-intf.intf'                                ,
        'standby-intf.group'                               ,
        'standby-intf.version'                             ,
        'standby-intf.state'                               ,
        'standby-intf.state-change'                        ,
        'standby-intf.last-change'                         ,
        'standby-intf.vaddr'                               ,
        'standby-intf.active-vmac'                         ,
        'standby-intf.active-virtual-mac-address-unknown'  ,
        'standby-intf.localc-mac'                          ,
        'standby-intf.local-virtual-mac-address-unknown'   ,
        'standby-intf.hello-time'                          ,
        'standby-intf.hold-time'                           ,
        'standby-intf.preemption'                          ,
        'standby-intf.active-rtr-ip'                       ,
        'standby-intf.active-rtr-priority'                 ,
        'standby-intf.active-router-active-router-unknown' ,
        'standby-intf.active-rtr-mac'                      ,
        'standby-intf.standby-rtr'                         ,
        'standby-intf.priority'                            ,
        'standby-intf.configured-priority'                 ,
        'standby-intf.group-name'                          ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

