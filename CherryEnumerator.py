#!/usr/bin/python3

"""
Author: @secfult

Mass Enumertor will discover and perform initial enumeration for all hosts in 
a given subnet and output a CherryTree file that is suitable for import.

Usage: 

For each discovered host, we will create a sub-node following the below
structure. The nmap output will be parsed and each open port will be added
under the enumeration node.

A separate file, CE-portactions.xml, will contain a many-to-many command 
mapping that can be run against those ports for additional enumeration (or 
exploitation).
e.g. Run Nikto against port 80 http and 8080 http

This additional output will show up under the relevant <NMAP PORT RESULT> node.


CherryTree XML output format guide

[BLAHBLAH] = Node label in Cherrytree
<BLAHBLAH> = Program-generated output, as either label or node content

[subnet <IP>/XX]
    [<IP> <HOSTNAME]
        [Enumeration]
            [nmap]
                <SCAN OUTPUT>
            [<NMAP PORT RESULT>]
                [<CE-portaction friendlyname>]
        [Exploitation]
        [Post-exploitation]
        [Privesc]
        [Goodies]
        [Software Versions]
        [Methodology]
        [Log Book]


MAIN FUNCTION

nmap host/network list given as argument

parse nmap output into usable form
    we need to store: IP, hostname, open ports, services

load CE-portactions.xml

if nmap finds any matches in that file, execute action
    This will be network-heavy, so multi-threading will increase performance

generate final XML file and output
"""

import os
import sys
import subprocess
from lxml import etree

OUTPUTDIR = "./CE-output"
NETRANGE = sys.argv[1]
NMAPOUTFILE = OUTPUTDIR + "/nmap.xml"

class Host(object):
    IPADDR = ""
    HOSTNAME = ""
    PORTS = []

    def print(self):
        print("IP address: " + self.IPADDR)
        print("Hostname: " + self.HOSTNAME)
        for port in self.PORTS:
            #print("Ports:")
            port.print_singleline()

class Port(object):
    PROTOCOL = ""
    PORTNUM = 0
    SERVICE = ""

    def print(self):
        print("Protocol: " + self.PROTOCOL)
        print("Port number: " + self.PORTNUM)
        print("Service name: " + self.SERVICE)

    def print_singleline(self):
        print(self.PORTNUM + "/" + self.PROTOCOL + " " + self.SERVICE)

def setup_output_dir():
    if not os.path.exists(OUTPUTDIR):
        os.makedirs(OUTPUTDIR)

def nmap_scan(hosts):
    print("Scanning network range: " + hosts)
    scan = subprocess.run(['nmap', '-oX', NMAPOUTFILE, hosts], stdout=subprocess.PIPE)
    return scan.stdout

def hostify_nmap_output(nmap_xml, hostlist):
    """
    Input: nmap scan file in XML format, list(Host)
    Output: list(Host)
    """

    xml = etree.parse(open(nmap_xml))
    hosts = xml.findall('host')

    # Iterate through each host in  the output
    for i in hosts:

        host = Host()

        # Grab IP
        for j in i.findall('address'):
            if j.get('addrtype') == "ipv4":
                host.IPADDR = j.get('addr')

        # Grab hostname
        host.HOSTNAME = (i.find('hostnames/hostname')).get('name')

        portlist = []

        # Get open ports and services
        for p in i.findall('ports/port'):
            port = Port()
            port.PROTOCOL = p.get('protocol')
            port.PORTNUM = p.get('portid')
            port.SERVICE = (p.find('service')).get('name')
            portlist.append(port)
            
        host.PORTS = portlist

        hostlist.append(host)

def 

setup_output_dir()

#nmap_output = nmap_scan(NETRANGE)
nmap_output = (open(NMAPOUTFILE)).read()

hostlist = []
hostify_nmap_output(NMAPOUTFILE, hostlist) # Should this be an assigned variable?

for host in hostlist:
    host.print()
    print("\n")

