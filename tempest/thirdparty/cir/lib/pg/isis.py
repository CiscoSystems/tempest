#    * * * WARNING - Auto generated file do not edit   * * *
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#
show_commands = {
    'iox': {
        'SHOW_CEF_PREFIX'            : 'show cef prefix',
        'SHOW_ISIS_PREFIX'           : 'show isis prefix',
        'SHOW_MPLS_FORWARDING_PREFIX': 'show mpls forwarding prefix',
        'SHOW_ROUTE_PREFIX'          : 'show route prefix',
    },
}

regex = {
    'iox': {
        #
        # SHOW_CEF_PREFIX ('show cef prefix')
        #
        'cef-prefix.prefix'            : r'([A-Fa-f0-9/:\.]+), version 2422, internal 0x4000001 \(ptr 0x5781aff4\) \[1\], 0x0 \(0x5780092c\), 0x0 \(0x0\)',
        'cef-prefix.firsthopprefix'    : r'\s+via\s+([A-Fa-f0-9:\.]+),\s+[-A-Za-z0-9\._/:]+, 8 dependencies, weight 0, class 0, backup \(remote\) \[flags 0x8300\]',
        'cef-prefix.firsthopinterface' : r'\s+via\s+[A-Fa-f0-9:\.]+,\s+([-A-Za-z0-9\._/:]+), 8 dependencies, weight 0, class 0, backup \(remote\) \[flags 0x8300\]',
        'cef-prefix.locallabel'        : r'\s+local label\s+(\d+)      labels imposed {\d+}',
        'cef-prefix.imposedlabel'      : r'\s+local label\s+\d+      labels imposed {(\d+)}',
        #
        # SHOW_ISIS_PREFIX ('show isis prefix')
        #
        'isis-prefix.prefix'            : r'L1\s+([A-Fa-f0-9/:\.]+) \[20/115\] medium priority',
        'isis-prefix.firsthopaddress'   : r'\s+via\s+([A-Fa-f0-9:\.]+),\s+[-A-Za-z0-9\._/:]+,\s+\w+, sid-value \[\d+\]',
        'isis-prefix.firsthopinterface' : r'\s+via\s+[A-Fa-f0-9:\.]+,\s+([-A-Za-z0-9\._/:]+),\s+\w+, sid-value \[\d+\]',
        'isis-prefix.firsthopname'      : r'\s+via\s+[A-Fa-f0-9:\.]+,\s+[-A-Za-z0-9\._/:]+,\s+(\w+), sid-value \[\d+\]',
        'isis-prefix.sidvalue'          : r'\s+via\s+[A-Fa-f0-9:\.]+,\s+[-A-Za-z0-9\._/:]+,\s+\w+, sid-value \[(\d+)\]',
        'isis-prefix.routername'        : r'\s+src\s+(\w+).00-00,\s+[A-Fa-f0-9:\.]+, nodal-sid-offset\s+\d+, R:\d+ N:\d+ P:\d+',
        'isis-prefix.routeraddress'     : r'\s+src\s+\w+.00-00,\s+([A-Fa-f0-9:\.]+), nodal-sid-offset\s+\d+, R:\d+ N:\d+ P:\d+',
        'isis-prefix.prefixindex'       : r'\s+src\s+\w+.00-00,\s+[A-Fa-f0-9:\.]+, nodal-sid-offset\s+(\d+), R:\d+ N:\d+ P:\d+',
        'isis-prefix.rflag'             : r'\s+src\s+\w+.00-00,\s+[A-Fa-f0-9:\.]+, nodal-sid-offset\s+\d+, R:(\d+) N:\d+ P:\d+',
        'isis-prefix.nflag'             : r'\s+src\s+\w+.00-00,\s+[A-Fa-f0-9:\.]+, nodal-sid-offset\s+\d+, R:\d+ N:(\d+) P:\d+',
        'isis-prefix.pflag'             : r'\s+src\s+\w+.00-00,\s+[A-Fa-f0-9:\.]+, nodal-sid-offset\s+\d+, R:\d+ N:\d+ P:(\d+)',
        #
        # SHOW_MPLS_FORWARDING_PREFIX ('show mpls forwarding prefix')
        #
        'mpls-prefix.locallabel'        : r'(\d+)\s+\d+       No ID\s+[-A-Za-z0-9\._/:]+    XA<firsthopaddress>12.1.0.1        0\s+',
        'mpls-prefix.outgoinglabel'     : r'\d+\s+(\d+)       No ID\s+[-A-Za-z0-9\._/:]+    XA<firsthopaddress>12.1.0.1        0\s+',
        'mpls-prefix.outgoinginterface' : r'\d+\s+\d+       No ID\s+([-A-Za-z0-9\._/:]+)    XA<firsthopaddress>12.1.0.1        0\s+',
        #
        # SHOW_ROUTE_PREFIX ('show route prefix')
        #
        'rib-received-prefix.prefix'            : r'Routing entry for\s+([A-Fa-f0-9/:\.]+)',
        'rib-received-prefix.protocol'          : r'\s+Known via "(\w+)\s+\w+", distance 115, metric 20, type level-1',
        'rib-received-prefix.instance'          : r'\s+Known via "\w+\s+(\w+)", distance 115, metric 20, type level-1',
        'rib-received-prefix.firsthopaddress'   : r'\s+([A-Fa-f0-9:\.]+), from 3.3.3.3, via\s+[-A-Za-z0-9\._/:]+,\s+\w+ \(\w+\)',
        'rib-received-prefix.firsthopinterface' : r'\s+[A-Fa-f0-9:\.]+, from 3.3.3.3, via\s+([-A-Za-z0-9\._/:]+),\s+\w+ \(\w+\)',
        'rib-received-prefix.pathtype'          : r'\s+[A-Fa-f0-9:\.]+, from 3.3.3.3, via\s+[-A-Za-z0-9\._/:]+,\s+(\w+) \(\w+\)',
        'rib-received-prefix.backuppathtype'    : r'\s+[A-Fa-f0-9:\.]+, from 3.3.3.3, via\s+[-A-Za-z0-9\._/:]+,\s+\w+ \((\w+)\)',
        'rib-received-prefix.labelhex'          : r'\s+Label:\s+((?:0x)?[a-fA-F0-9]+) \(\d+\)',
        'rib-received-prefix.label'             : r'\s+Label:\s+(?:0x)?[a-fA-F0-9]+ \((\d+)\)',
        'rib-received-prefix.locallabel'        : r'\s+Local Label:\s+WH<locallabelhex>X0x3e85 \((\d+)\)',
    },
}
