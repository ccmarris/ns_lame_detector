============================
DNS Lame Delegation Detector
============================

| Version: 0.1.1
| Author: Chris Marrison
| Email: chris@infoblox.com

Description
-----------

A python class to assist with detecting lame delegations for DNS domains.
The class can be used within your own scripts or the script can be run 
directly from the command line.

This was inspired by Infoblox Threat Intel and Eclypsium who published 
information on the Sitting Ducks attack:

https://blogs.infoblox.com/threat-intelligence/who-knew-domain-hijacking-is-so-easy/


Prerequisites
-------------

Python 3.8+
dnspython 2.6.1+


Installing Python
~~~~~~~~~~~~~~~~~

You can install the latest version of Python 3.x by downloading the appropriate
installer for your system from `python.org <https://python.org>`_.

.. note::

  If you are running MacOS Catalina (or later) Python 3 comes pre-installed.
  Previous versions only come with Python 2.x by default and you will therefore
  need to install Python 3 as above or via Homebrew, Ports, etc.

  By default the python command points to Python 2.x, you can check this using 
  the command::

    $ python -V

  To specifically run Python 3, use the command::

    $ python3


.. important::

  Mac users will need the xcode command line utilities installed to use pip3,
  etc. If you need to install these use the command::

    $ xcode-select --install

.. note::

  If you are installing Python on Windows, be sure to check the box to have 
  Python added to your PATH if the installer offers such an option 
  (it's normally off by default).


Modules
~~~~~~~

Non-standard modules:

    - dnspython version 2.6.1 or above

Complete list of modules::

  import logging
  import argparse
  import sys
  import csv
  import dns.resolver
  import dns.rcode



Installation
------------

The simplest way to install and maintain the tools is to clone this 
repository::

    % git clone https://github.com/ccmarris/ns_lame_detector


Alternative you can download as a Zip file.


Usage
-----

The script support -h or --help on the command line to access the options 
available::

  % ./ns_lame_detector.py --help
  usage: ns_lame_detector.py [-h] [-z ZONE] [-d]

  DNS Lame Server Check

  options:
    -h, --help            show this help message and exit
    -z ZONE, --zone ZONE  Zone to perform checks against
    -d, --debug           Enable debug messages


Examples
--------

Simple examples show below::

  % ./ns_lame_detector.py --zone infoblox.com

  Results for the domain: infoblox.com

  Fantastic: No lame servers detected!

  Nameserver:  Status
  ns5.infoblox.com.: AUTHORITATIVE
  ns6.infoblox.com.: AUTHORITATIVE
  ns1.infoblox.com.: AUTHORITATIVE
  ns7.infoblox.com.: AUTHORITATIVE


Bulk check to STDOUT::

  % ./ns_lame_detector.py --bulk domains
  2024-08-04 08:47:10,536 INFO: Checking infoblox.com domain
  2024-08-04 08:47:11,530 INFO: Checking google.com domain
  zone,nameserver,status
  infoblox.com,ns5.infoblox.com.,AUTHORITATIVE
  infoblox.com,ns6.infoblox.com.,AUTHORITATIVE
  infoblox.com,ns7.infoblox.com.,AUTHORITATIVE
  infoblox.com,ns1.infoblox.com.,AUTHORITATIVE
  google.com,ns3.google.com.,AUTHORITATIVE
  google.com,ns2.google.com.,AUTHORITATIVE
  google.com,ns4.google.com.,AUTHORITATIVE
  google.com,ns1.google.com.,AUTHORITATIVE

Bulk check to CSV file::

  % ./ns_lame_detector.py --bulk domains --out bulk_report.csv
  2024-08-04 08:47:10,536 INFO: Checking infoblox.com domain
  2024-08-04 08:47:11,530 INFO: Checking google.com domain
  2024-08-04 08:47:11,540 INFO: Bulk check complete


License
-------

This project is licensed under the 2-Clause BSD License
- please see LICENSE file for details.


Aknowledgements
---------------

Thanks to Infoblox Threat Intel for their amazing work on Sitting Duck.
Thanks to John Steele for letting me sanity check my process.
Thanks for Henrik Kentsson for asking about a script to test for lame
delegations.


