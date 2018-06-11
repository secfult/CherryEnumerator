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
e.g. Run Nikto against port 80, any 'http' service, and port 8080

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

OUTPUTDIR = "./output"
NETRANGE = sys.argv[1]
NMAPOUTFILE = OUTPUTDIR + "/nmap.xml"
ACTIONSFILE = "actions.xml"

class Host(object):
    IPADDR = ""
    HOSTNAME = ""
    PORTS = []
    ACTIONS = []

    def print(self):
        print("IP address: " + self.IPADDR)
        print("Hostname: " + self.HOSTNAME)
        for port in self.PORTS:
            #print("Ports:")
            port.print_singleline()

    def perform_actions(self):
        for action in self.ACTIONS:
            print("Running: " + str(action.COMMAND.split(" ")))
            result = subprocess.run(action.COMMAND.split(" "), stdout=subprocess.PIPE)
            action.OUTPUT = str(result.stdout)
            print("Result: " + action.OUTPUT)

    def append_unique_action(self, action):
        commandpresentflag = 0
        
        for hostaction in self.ACTIONS:
            if action.FRIENDLYNAME == hostaction.FRIENDLYNAME: # this would double up, ignore subsequent actions with same friendlyname
                commandpresentflag = 1
        if not commandpresentflag:
            self.ACTIONS.append(action)
            print("IP " + host.IPADDR + " will have '" + action.COMMAND + "' run against port " + port.PORTNUM)

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

class Action(object):
    TARGETPORT = 0
    TARGETSERVICE = ""
    COMMAND = ""
    FRIENDLYNAME = ""
    OUTPUT = ""

    def print(self):
        print("Action: " + str(self.TARGETPORT) + "/" + self.TARGETSERVICE + "/" + self.FRIENDLYNAME + "/" + self.COMMAND)

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

def load_actions(fileloc):
    """
    Loads the actions file and returns a list of Action's
    """
    actionfile = open(fileloc)
    #actions = actionfile.read()
    xml = etree.parse(actionfile)

    actions = xml.findall('mapping')

    actionlist = []
    for action in actions:
        actionitem = Action()
        
        if action.findtext('port') is not None:
            actionitem.TARGETPORT = action.findtext('port')
        if action.findtext('service') is not None:
            actionitem.TARGETSERVICE = action.findtext('service')
        actionitem.COMMAND = action.findtext('command')
        actionitem.FRIENDLYNAME = (action.find('command')).get('friendlystring')

        actionlist.append(actionitem)

    return actionlist


setup_output_dir()

nmap_output = nmap_scan(NETRANGE)
#nmap_output = (open(NMAPOUTFILE)).read()

hostlist = []
hostify_nmap_output(NMAPOUTFILE, hostlist) # Should this be an assigned variable?

for host in hostlist:
    host.print()
    print("\n")

actions = load_actions(ACTIONSFILE)

for action in actions:
    action.print()

# Match enumerated hosts against the ports/services found in actionfile
for host in hostlist:
    #Store list of actions to run against the host so we don't double up
    #hostactions = []

    for port in host.PORTS:
        for action in actions:
            #print(str(port.PORTNUM) + " " + str(action.TARGETPORT) + " " + port.SERVICE + " " +action.TARGETSERVICE)
            if port.PORTNUM == action.TARGETPORT:
                action.COMMAND = action.COMMAND.replace('[IP]', host.IPADDR)

                host.append_unique_action(action)

            if port.SERVICE == action.TARGETSERVICE:
                action.COMMAND = action.COMMAND.replace('[IP]', host.IPADDR)

                host.append_unique_action(action)

# Run enumeration tasks against hosts
for host in hostlist:
    host.perform_actions()

# Load CherryTree template file

