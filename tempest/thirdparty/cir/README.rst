
Copyright (c) 2015 by Cisco Systems, Inc.
All rights reserved.

April 2015,     R.A. Winters <riwinter@cisco.com>

OpenStack-DevTest at Cisco
=============================

This repo contains a set of tests and support code to be run against a live
OpenStack cloud to verify Cisco products in that cloud using Cisco 
internal tools within the OpenStack Tempest test harness.

The OpenStack community has developed a test harness called Tempest.  The 
Tempest test harness provides a lot of support for creating many stack
elements (servers, networks, routers...) used during testing.  It also has
been integrated into many Continuous Integration (CI) systems including
those used by Cisco to test OpenStack.  Tempest is built using Python 
as it's coding language.

Cisco has test harnesses based on Python that enables test engineers
to inspect and control Cisco devices such as Nexus switches and ASR/CSR
routers.  The Cisco test harnesses are pyATS and XRUT.  pyATS at the 
time of this writing is just coming online and uses a lot of pass through
calls to older Tcl based technology.  However pyATS does have official  
corporate support so it may at some point be reconsidered here.  
XRUT has been in use for some time, has a large user base and is 
incorporated into Cisco main regression systems.  XRUT is also completely 
based on Python so it seems a natural fit with Tempest.

The problem arises in that Cisco internal tools cannot be exposed
to the public OpenStack community.  This repo is designed to work 
within the Tempest code tree to add the Cisco specific code needed
to use/support the Cisco internal tools being used.

This repo should NEVER be delivered outside of Cisco Systems and tests
developed here should never be up streamed without consulting Cisco
legal.

Setup:
=====

OpenStack Controller Node:
=========================

XRUT must be installed on the node where the Tempest tests are going 
to be run from.  This is usually the controller node in the
stack.

For consistency install XRUT in /opt/ws/xrut on the controller node.

You can down load a tar ball from our internal server using:

Then simply untar it in the /opt/ws directory

Make sure you give access permissions to this directory


Tempest setup:
=============
This repo is designed to be cloned into the Tempest clone, therefore you should first
clone the cisco-openstack/tempest repo.

The basic steps are:
 
    1. Clone cisco-openstack/tempest
    2. cd to tempest/tempest/thirdparty
    3. Clone os-devtest/OpenStack-DevTest.git
        git clone git clone ssh://<your-cec-login>@sjc-apl-gerrit3.cisco.com:29418/os-devtest/OpenStack-DevTest cisco
    4. Copy Cisco's git hooks
        scp -p -P 29418 <your-cec-login>@sjc-apl-gerrit3.cisco.com:hooks/commit-msg cisco/.git/hooks/commit-msg
    5. Add the remote gerrit
        git remote add gerrit ssh://<your-cec-login>@sjc-apl-gerrit3.cisco.com:29418/os-devtest/OpenStack-DevTest
    6. Run git review -s
    7. Create branch as necessary.


You should now have the ability to run any of the tests in the repo from 
Tempest on the controller node.  Of course you will need to update the 
tempest.conf file int tempest/etc with the correct IPs and connections of
your particular Cisco devices.  The configuraion steps will not doubt 
change over time and therefore won't be convered here.


References:
==========

XRUT
http://wwwin-eng.cisco.com/Eng/NSSTG/WWW/XRUT/xrut-doc/
http://wikicentral.cisco.com/display/XRUT/XRUT+Project
http://wikicentral.cisco.com/display/XRUT/XRUT+Learning+Center

Cisco's Software Configuration Management Infrastructure (SCMI)
http://wikicentral.cisco.com/display/PROJECT/SCMCI+Gerrit
http://wikicentral.cisco.com/display/PROJECT/SCMCI%20-%20Centrally%20Supported%20Git

Cisco Openstack Repo's
http://wikicentral.cisco.com/display/OPENSTACK/cisco-openstack+repo+for+cisco+specific+features

