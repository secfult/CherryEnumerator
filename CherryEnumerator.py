"""
Mass Enumertor will discover and perform initial enumeration for all hosts in 
a given subnet and output a CherryTree file that is suitable for import.

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
        [Exploitation]
        [Post-exploitation]
        [Privesc]
        [Goodies]
        [Software Versions]
        [Methodology]
        [Log Book]
"""


OUTPUTDIR = "./CE-output"

