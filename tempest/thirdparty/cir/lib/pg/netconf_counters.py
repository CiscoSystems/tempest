#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_NETCONF_COUNTERS': 'show netconf counters',
    },
}
regex = {
    'ios': {
        #
        # SHOW_NETCONF_COUNTERS ('show netconf counters')
        #
        'netconf-counters.attempts'            : r'Connection Attempts:(\d+):\s+rejected:\d+ no-hello:\d+ success:\d+',
        'netconf-counters.rejected'            : r'Connection Attempts:\d+:\s+rejected:(\d+) no-hello:\d+ success:\d+',
        'netconf-counters.no-hello'            : r'Connection Attempts:\d+:\s+rejected:\d+ no-hello:(\d+) success:\d+',
        'netconf-counters.success'             : r'Connection Attempts:\d+:\s+rejected:\d+ no-hello:\d+ success:(\d+)',
        'netconf-counters.transactions'        : r'(Transactions)',
        'netconf-counters.transactions-total'  : r'\s+total:(\d+), success:\d+, errors:\d+',
        'netconf-counters.transaction-success' : r'\s+total:\d+, success:(\d+), errors:\d+',
        'netconf-counters.transaction-errors'  : r'\s+total:\d+, success:\d+, errors:(\d+)',
        'netconf-counters.in-use'              : r'\s+in-use\s+(\d+) 	invalid-value\s+\d+ 	too-big\s+\d+',
        'netconf-counters.invalid-value'       : r'\s+in-use\s+\d+ 	invalid-value\s+(\d+) 	too-big\s+\d+',
        'netconf-counters.too-big'             : r'\s+in-use\s+\d+ 	invalid-value\s+\d+ 	too-big\s+(\d+)',
        'netconf-counters.missing-attr'        : r'\s+missing-attribute\s+(\d+) 	bad-attribute\s+\d+ 	unknown-attribute\s+\d+',
        'netconf-counters.bad-attr'            : r'\s+missing-attribute\s+\d+ 	bad-attribute\s+(\d+) 	unknown-attribute\s+\d+',
        'netconf-counters.unknow-attr'         : r'\s+missing-attribute\s+\d+ 	bad-attribute\s+\d+ 	unknown-attribute\s+(\d+)',
        'netconf-counters.missing-element'     : r'\s+missing-element\s+(\d+) 	bad-element\s+\d+ 	unknown-element\s+\d+',
        'netconf-counters.bad-element'         : r'\s+missing-element\s+\d+ 	bad-element\s+(\d+) 	unknown-element\s+\d+',
        'netconf-counters.unknown-element'     : r'\s+missing-element\s+\d+ 	bad-element\s+\d+ 	unknown-element\s+(\d+)',
        'netconf-counters.unknown-namespace'   : r'\s+unknown-namespace\s+(\d+) 	access-denied\s+\d+ 	lock-denied\s+\d+',
        'netconf-counters.access-denied'       : r'\s+unknown-namespace\s+\d+ 	access-denied\s+(\d+) 	lock-denied\s+\d+',
        'netconf-counters.lock-denied'         : r'\s+unknown-namespace\s+\d+ 	access-denied\s+\d+ 	lock-denied\s+(\d+)',
        'netconf-counters.resource-denied'     : r'\s+resource-denied\s+(\d+) 	rollback-failed\s+\d+ 	data-exists\s+\d+',
        'netconf-counters.rollback-failed'     : r'\s+resource-denied\s+\d+ 	rollback-failed\s+(\d+) 	data-exists\s+\d+',
        'netconf-counters.data-exists'         : r'\s+resource-denied\s+\d+ 	rollback-failed\s+\d+ 	data-exists\s+(\d+)',
        'netconf-counters.data-missing'        : r'\s+data-missing\s+(\d+) 	operation-not-supported\s+\d+ 	operation-failed\s+\d+',
        'netconf-counters.op-not-supported'    : r'\s+data-missing\s+\d+ 	operation-not-supported\s+(\d+) 	operation-failed\s+\d+',
        'netconf-counters.op-failed'           : r'\s+data-missing\s+\d+ 	operation-not-supported\s+\d+ 	operation-failed\s+(\d+)',
        'netconf-counters.partial-op'          : r'\s+partial-operation\s+(\d+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_NETCONF_COUNTERS ('show netconf counters')
        #
        'netconf-counters.attempts'            ,
        'netconf-counters.rejected'            ,
        'netconf-counters.no-hello'            ,
        'netconf-counters.success'             ,
        'netconf-counters.transactions'        ,
        'netconf-counters.transactions-total'  ,
        'netconf-counters.transaction-success' ,
        'netconf-counters.transaction-errors'  ,
        'netconf-counters.in-use'              ,
        'netconf-counters.invalid-value'       ,
        'netconf-counters.too-big'             ,
        'netconf-counters.missing-attr'        ,
        'netconf-counters.bad-attr'            ,
        'netconf-counters.unknow-attr'         ,
        'netconf-counters.missing-element'     ,
        'netconf-counters.bad-element'         ,
        'netconf-counters.unknown-element'     ,
        'netconf-counters.unknown-namespace'   ,
        'netconf-counters.access-denied'       ,
        'netconf-counters.lock-denied'         ,
        'netconf-counters.resource-denied'     ,
        'netconf-counters.rollback-failed'     ,
        'netconf-counters.data-exists'         ,
        'netconf-counters.data-missing'        ,
        'netconf-counters.op-not-supported'    ,
        'netconf-counters.op-failed'           ,
        'netconf-counters.partial-op'          ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)


