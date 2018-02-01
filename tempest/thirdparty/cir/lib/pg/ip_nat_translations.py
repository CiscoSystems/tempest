#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
import parsercore as pcore
show_commands = {
    'ios': {
        'SHOW_IP_NAT_TRANSLATIONS': ' show ip nat translations',
    },
}
regex = {
    'ios': {
        #
        # SHOW_IP_NAT_TRANSLATIONS (' show ip nat translations')
        #
        'nat-translations.protocol'       : r'(\S+)\s+\S+\s+\S+\s+\S+\s+\S+',
        'nat-translations.inside-global'  : r'\S+\s+(\S+)\s+\S+\s+\S+\s+\S+',
        'nat-translations.inside-local'   : r'\S+\s+\S+\s+(\S+)\s+\S+\s+\S+',
        'nat-translations.outside-local'  : r'\S+\s+\S+\s+\S+\s+(\S+)\s+\S+',
        'nat-translations.outside-global' : r'\S+\s+\S+\s+\S+\s+\S+\s+(\S+)',
        'nat-translations.total-key'      : r'(Total) number of translations:\s+\d+',
        'nat-translations.total'          : r'Total number of translations:\s+(\d+)',

    },
}
regex_tags = {
    'ios': [
        #
        # SHOW_IP_NAT_TRANSLATIONS (' show ip nat translations')
        #
        'nat-translations.protocol'       ,
        'nat-translations.inside-global'  ,
        'nat-translations.inside-local'   ,
        'nat-translations.outside-local'  ,
        'nat-translations.outside-global' ,
        'nat-translations.total-key'      ,
        'nat-translations.total'          ,

    ],
}
pcore.extend (regex, show_commands, regex_tags)

