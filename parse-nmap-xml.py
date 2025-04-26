#!/usr/bin/env python3
# Author: Aaron Lesmeister
# Date: 2020.12.07
# File: parse-nmap-xml.py
# Purpose: Parse Nmap XML output files from 'slober.sh' to CSV for reporting.
#

import os
import sys
import re
import argparse
import csv
import datetime
import xml.etree.ElementTree as ET 

# ---- Global Variables ---- #
__version__ = "2.1.4"
cwd = os.getcwd()
now = datetime.datetime.now()
now = now.strftime("%Y%m%d%H%M%S")
ippat = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
# ------------------------------------

# ---- Parser Functions ---- #

########################################
# Parse MSSQL Issues
def parseMssql(INFILE, OUT_PRE, VERBOSE):

    # Issues Parsed (NSE Script):
    #   - Microsoft SQL Version (ms-sql-info)
    #   - Unprotected Microsoft SQL Instance (ms-sql-empty-password)
    
    verbose_flag = VERBOSE
    infile = INFILE
    if OUT_PRE == None or OUT_PRE == "":
        ofp = ""
    else:
        ofp = OUT_PRE + "-"

    outfile = open((os.path.join(cwd, ofp + "reporting-mssql-issues_" + now + ".csv")), "w")
    writer = csv.writer(outfile, delimiter=',')
    writer.writerow( ('IP Address', 'Host Name', 'Service', 'Version', 'Full Product', 'Vulnerability') )

    # Parse MSSQL Issues
    print("   [+] Parsing Nmap XML for Microsoft SQL Issues.")

    tree = ET.ElementTree(file=infile)
    root = tree.getroot()

    # Variables for ADX ID checks
    isADX = ""
    versVulnName = ""
    svc = ""

    for node in root.iter('host'):
        for address in node.iter('address'):
            host = address.get('addr')
            if re.match(ippat, host):
                for port in node.iter('port'):
                    portid = port.attrib.get('portid')
                    for script in node.iter('script'):
                        scriptid = script.attrib.get('id')

                        # Azure Data Exporter (ADX) Update
                        #   We'll check this first so we can properly tag these instances to avoid false positives for MSSQL
                        # ADX runs on TCP1433 and emulates MSSQL, along with the TDS protocol. Because of this emulation, ADX will respond the same as any other MSSQL server and provide
                        #   a version number, sql server type, patch level, and so on. ADX is not, however, actually running MSSQL so this results in a false positive, especially since
                        #   ADX commonly responds with a deprecated version. At the time of writing, checking the TLS certificate information for TCP1433 is the most reliable/accurate
                        #   method for differentiating between ADX and actual MSSQL instances. 

                        # Parse the obtained TLS Cert.
                        if scriptid == "ssl-cert":

                            # ADX *should* always have Subject Alt Names with "kusto.windows.net" or "kustomfa.windows.net"
                            if "kusto.windows.net" in script.attrib.get('output'):
                                isADX = "1"
                                if verbose_flag is True:
                                    print("        > " + host + " : Possibly Azure Data Exporter -> \"kusto.windows.net\" observed in certificate output.")
                                writer.writerow( (host, "<HOSTNAME>", "TCP" + portid + " (ADX)", "kusto.windows.net", "Possible Azure Data Exporter Instance - Subject Alt Name") )
                            # ADX TLS Certificate *should* show something like "Issuer: commonName=Microsoft Azure RSA TLS Issuing CA"
                            for tabkey in script.iter('table'):
                                if tabkey.attrib.get('key') == "issuer":
                                    for elem in tabkey.iter('elem'):
                                        if elem.attrib.get('key') == "commonName":
                                            cert_issuer = elem.text.replace("\\x00", "")
                                            if "Azure" in cert_issuer:
                                                isADX = "2"
                                                writer.writerow( (host, "<HOSTNAME>", "TCP" + portid + " (ADX)", cert_issuer, "Possible Azure Data Exporter Instance - Certificate Issuer") )
                                                if verbose_flag is True:
                                                    print("        > " + host + " : Possibly Azure Data Exporter -> Certificate Issuer: " + cert_issuer)

                        # Update output based on SSL Info
                        if isADX != "":
                            versVulnName = "Azure Data Exporter (ADX) Detected (Instance is not MSSQL)"
                            svc = " (ADX)"
                        else:
                            versVulnName = "Microsoft SQL Server Version Detected"
                            svc = " (MSSQL)"

                        # Get MSSQL Instance product name and version nunmber
                        if scriptid == "ms-sql-info":
                            for elem in script.iter('elem'):
                                if elem.attrib.get('key') == "name":
                                    mssql_name = elem.text
                                if elem.attrib.get('key') == "number":
                                    mssql_vers = elem.text

                            writer.writerow( (host, "<HOSTNAME>", "TCP" + portid + svc, mssql_vers, mssql_name + " " + mssql_vers, versVulnName) )
                            if verbose_flag is True:
                                if isADX != "":
                                    print("        > " + host + " is a Microsoft Azure Data Exporter Instance (not MSSQL)")
                                else:
                                    print("        > " + host + " is running " + mssql_name + " Version " + mssql_vers + " on TCP" + portid)
                        
                        # Check for blank SA password.
                        if scriptid == "ms-sql-empty-password":
                            if "Login Success" in script.attrib.get('output'):
                                writer.writerow( (host, "<HOSTNAME>", "TCP" + portid + " (MSSQL)", "'sa' User Blank Password", "Unauthenticated Microsoft SQL Instance") )
                                if verbose_flag is True:
                                    print("        > " + host + " TCP" + portid + " (MSSQL)" + " 'sa' user has an empty password!")

        # Reset isADX var
        isADX = ""
                

    # Close output file
    outfile.close()   
    print("   [+] Done") 

# END Parse MSSQL
########################################

########################################
# Parse MySQL Issues
def parseMysql(INFILE, OUT_PRE, VERBOSE):

    # Issues Parsed (NSE Script):
    #   - MySQL Version (mysql-info)
    
    verbose_flag = VERBOSE
    infile = INFILE
    if OUT_PRE == None or OUT_PRE == "":
        ofp = ""
    else:
        ofp = OUT_PRE + "-"

    outfile = open((os.path.join(cwd, ofp + "reporting-mysql-issues_" + now + ".csv")), "w")
    writer = csv.writer(outfile, delimiter=',')
    writer.writerow( ('IP Address', 'Host Name', 'Service', 'Version', 'Full Product', 'Vulnerability') )

    # Parse MYSQL Issues
    print("   [+] Parsing Nmap XML for MySQL Issues.")

    tree = ET.ElementTree(file=infile)
    root = tree.getroot()

    mysql_ver = ""

    for node in root.iter('host'):
        for address in node.iter('address'):
            host = address.get('addr')
            if re.match(ippat, host):
                for port in node.iter('port'):
                    portid = port.attrib.get('portid')
                    for script in node.iter('script'):
                        scriptid = script.attrib.get('id')

                        # Get MySQL version nunmber
                        if scriptid == "mysql-info":
                            for elem in script.iter('elem'):
                                if elem.attrib.get('key') == "Version":
                                    mysql_ver = elem.text

                            if mysql_ver is not None:
                                writer.writerow( (host, "<HOSTNAME>", "TCP" + portid + " (MySQL)", mysql_ver, "MySQL Server Version Detected") )
                                if verbose_flag is True:
                                    print("        > " + host + " is running MySQL version " + mysql_ver + " on TCP" + portid)

    # Close output file
    outfile.close()   
    print("   [+] Done") 

# END Parse MySQL
########################################

########################################
# Parse NTP Issues
def parseNtp(INFILE, OUT_PRE, VERBOSE):

    # Issues Parsed (NSE Script):
    #   - 
    
    verbose_flag = VERBOSE
    infile = INFILE
    if OUT_PRE == None or OUT_PRE == "":
        ofp = ""
    else:
        ofp = OUT_PRE + "-"

    outfile = open((os.path.join(cwd, ofp + "reporting-ntp-issues_" + now + ".csv")), "w")
    writer = csv.writer(outfile, delimiter=',')
    writer.writerow( ('IP Address', 'Host Name', 'Service', 'Details', 'Vulnerability') )

    # Parse NTP Issues
    print("   [+] Parsing Nmap XML for NTP Issues.")

    tree = ET.ElementTree(file=infile)
    root = tree.getroot()

    # NTP Clock Vars
    ntp_timestamp = ""
    ntp_version = ""
    ntp_arch = ""
    ntp_os = ""
    ntp_refid = ""
    # NTP Monlist
    ntp_monlist = ""

    for node in root.iter('host'):
        for address in node.iter('address'):
            host = address.get('addr')
            # Skip instances where a MAC address in address.get('addr')
            if re.match(ippat, host):
                for script in node.iter('script'):
                    scriptid = script.attrib.get('id')

                    # Get NTP Clock Variables 
                    if scriptid == "ntp-info":
                        for elem in script.iter('elem'):
                            if elem.attrib.get('key') == "receive time stamp":
                                ntp_timestamp = "Timestamp: " + elem.text + ";;; "
                            if elem.attrib.get('key') == "version":
                                ntp_version = "Version: " + elem.text + ";;; "
                            if elem.attrib.get('key') == "processor":
                                ntp_arch = "Processor: " + elem.text + ";;; "
                            if elem.attrib.get('key') == "system":
                                ntp_os = "OS: " + elem.text + ";;; "
                            if elem.attrib.get('key') == "refid":
                                ntp_refid = "Peer RefID: " + elem.text
                            
                        ntp_vars = ntp_timestamp + ntp_version + ntp_os + ntp_arch + ntp_refid

                        if ntp_vars is not None:
                            writer.writerow( (host, "<HOSTNAME>", "UDP123 (NTP)", ntp_vars, "NTP Clock Variables Information Disclosure") )
                            if verbose_flag is True:
                                print("        > " + host + " NTP Clock Variables: " + ntp_vars)
                    
                    # Get Monlist Output
                    if scriptid == "ntp-monlist":
                        if "Target" in script.attrib.get('output') or "Private" in script.attrib.get('output'):
                            ntp_monlist = script.attrib.get('output')
                            #ntp_monlist = ' '.join(ntp_monlist.split())
                            ntp_monlist = re.sub(r'\s+', ' ', ntp_monlist)
                            writer.writerow( (host, "<HOSTNAME>", "UDP123 (NTP)", ntp_monlist, "NTP Daemon Monlist Denial of Service") )
                            if verbose_flag is True:
                                print("        > " + host + " NTP Monlist Enabled (DOS): " + ntp_monlist)

    # Close output file
    outfile.close()   
    print("   [+] Done") 

# END Parse NTP
########################################

########################################
# Parse SMB Issues
def parseSmb(INFILE, OUT_PRE, VERBOSE):

    # Issues parsed (NSE Script):
    #   - SMB Signing not Required (smb-security-mode,smb2-security-mode)
    #   - SMBv1 Protocol Enabled (smb-protocols)
    # NSE Scripts not Parsed:
    #   - smb-enum-domains,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-server-stats,smb-system-info,smb2-capabilities
    
    verbose_flag = VERBOSE
    infile = INFILE
    craig_robinson = ""
    if OUT_PRE == None or OUT_PRE == "":
        ofp = ""
    else:
        ofp = OUT_PRE + "-"

    outfile = open((os.path.join(cwd, ofp + "reporting-smb-issues_" + now + ".csv")), "w")
    writer = csv.writer(outfile, delimiter=',')
    writer.writerow( ('IP Address', 'Host Name', 'Service', 'Details', 'Vulnerability') )

    # Parse SMB Issues
    print("   [+] Parsing Nmap XML for SMB Issues.")

    tree = ET.ElementTree(file=infile)
    root = tree.getroot()

    for node in root.iter('host'):
        for address in node.iter('address'):
            host = address.get('addr')
            #print ("[DEBUG]> host = " + host)

            # Skip instances where a MAC address in address.get('addr')
            if re.match(ippat, host):
                for script in node.iter('script'):
                    scriptid = script.attrib.get('id')

                    # Parse SMBv1
                    if scriptid == "smb-protocols":
                        for key in script.iter('elem'):
                            if key.text == 'NT LM 0.12 (SMBv1) [dangerous, but default]':
                                #print ("DEBUG: " + host + " : " + key.text)
                                writer.writerow( (host, "<HOSTNAME>", "TCP445 (SMB)","NT LM 0.12 (SMBv1 Enabled)","SMBv1 Protocol Enabled") )
                                if verbose_flag is True:
                                    print("        > " + host + " : SMBv1 Supported : " + key.text)

                    # Parse SMB Signing
                    seent_it = ""
                    if scriptid == "smb-security-mode":
                        for key in script.iter('elem'):
                            if key.attrib.get('key') == "message_signing":
                                # message_signing is either: disabled, supported, or required
                                if key.text != "required":
                                    writer.writerow( (host, "<HOSTNAME>", "TCP445 (SMB)","SMB Signing not Required", "SMB Signing not Required") )
                                    craig_robinson = host # Trust Craig.
                                    if verbose_flag is True:
                                        print("        > " + host + " : SMB Signing not Required : " + key.text)
                    # If Criag hasn't seent it, look at smb2.
                    if host not in craig_robinson:
                        if scriptid == "smb2-security-mode":
                            for key in script.iter('elem'):
                                if "signing enabled and required" not in key.text:
                                    writer.writerow( (host, "<HOSTNAME>", "TCP445 (SMB)","SMB2 Signing not Required", "SMB Signing not Required") )
                                    if verbose_flag is True:
                                        print("        > " + host + " : SMB Signing not Required : " + key.text)
    
    # Close output file
    outfile.close()   
    print("   [+] Done")                
    
# END Parse SMB
########################################

########################################
# Parse SMTP Issues
def parseSmtp(INFILE, OUT_PRE, VERBOSE):

    # Issues parsed (NSE Script):
    #   - SMTP Open Mail Relaying Allowed (smtp-open-relay)
    #   - Information Disclosure via External NTLM Authentication (smtp-ntlm-info)
    #   - SMTP EXPN/VRFY Information Disclosure (smtp-enum-users)
    # Info parsed (NSE script):
    #   - Available SMTP Commands (smtp-commands)
    
    verbose_flag = VERBOSE
    infile = INFILE
    if OUT_PRE == None or OUT_PRE == "":
        ofp = ""
    else:
        ofp = OUT_PRE + "-"

    outfile = open((os.path.join(cwd, ofp + "reporting-smtp-issues_" + now + ".csv")), "w")
    writer = csv.writer(outfile, delimiter=',')
    writer.writerow( ('IP Address', 'Host Name', 'Service', 'Details', 'Vulnerability') )

    # Parse SMTP Issues
    print("   [+] Parsing Nmap XML for SMTP Issues.")

    tree = ET.ElementTree(file=infile)
    root = tree.getroot()

    for node in root.iter('host'):
        for address in node.iter('address'):
            host = address.get('addr')
            #print ("[DEBUG]> host = " + host)

            # Skip instances where a MAC address in address.get('addr')
            if re.match(ippat, host):
                for port in node.iter('port'):
                    portid = port.attrib.get('portid')
                    
                    # Port output for reporting
                    if "25" in portid:
                        write_port = "TCP25 (SMTP)"
                    elif "465" in portid:
                        write_port = "TCP465 (SUBMISSION)"
                    elif "587" in portid:
                        write_port = "TCP587 (SMTPS)"
                    else:
                        write_port = "TCP" + port + " (SMTP)"

                    # Iterate through scripts
                    for script in node.iter('script'):
                        scriptid = script.attrib.get('id')

                        # Parse SMTP Commands
                        if scriptid == "smtp-commands":
                            if "This server supports the following commands:" in script.attrib.get('output'):
                                smtp_cmds = script.attrib.get('output')
                                # Define the boundaries for extracting data from output.
                                smtp_cmd_output_start = "This server supports the following commands: "
                                smtp_cmd_output_end = " \"/>"
                                smtp_cmds = smtp_cmds[smtp_cmds.find(smtp_cmd_output_start):smtp_cmds.rfind(smtp_cmd_output_end)]
                                smtp_cmds = smtp_cmds.replace("This server supports the following commands: ", "")
                                smtp_cmds = smtp_cmds.replace(" ",";;; ")

                                writer.writerow( (host, "<HOSTNAME>", write_port, smtp_cmds, "[INFO] Supported SMTP Commands") )
                                if verbose_flag is True:
                                    print("        > " + host + " : Supported SMTP Commands : " + smtp_cmds)
                        
                        # Parse Enumerated Users
                        if scriptid == "smtp-enum-users":
                            if "EXPN," in script.attrib.get('output') or "VRFY," in script.attrib.get('output') or "RCPT" in script.attrib.get('output'):
                                smtp_users = script.attrib.get('output')
                                smtp_users = smtp_users.replace("\n","")
                                smtp_users = re.sub(r"^  ","",smtp_users)
                                smtp_users = smtp_users.replace(", ",":")
                                smtp_users = smtp_users.replace("  ",";;; ")

                                writer.writerow( (host, "<HOSTNAME>", write_port, smtp_users, "SMTP EXPN/VRFY/RCPT Information Disclosure") )
                                if verbose_flag is True:
                                    print("        > " + host + " : SMTP User Enumeration : " + smtp_users)

                        # Parse SMTP Open Relay
                        if scriptid == "smtp-open-relay":
                            if "Server is an open relay" in script.attrib.get('output'):

                                writer.writerow( (host, "<HOSTNAME>", write_port, "Open Mail Relay", "[POTENTIAL] SMTP Open Mail Relaying Allowed") )
                                if verbose_flag is True:
                                    print("        > " + host + " : SMTP Open Mail Relaying Allowed")

                        # Parse SMTP NTLM Info
                        if scriptid == "smtp-ntlm-info":
                            if script.attrib.get('output'):
                                smtp_info = script.attrib.get('output')
                                smtp_info = re.sub(r"^\n  ","",smtp_info)
                                smtp_info = smtp_info.replace("\n  ",";;; ")
                                smtp_info = smtp_info.replace("_"," ")

                                writer.writerow( (host, "<HOSTNAME>", write_port, smtp_info, "Information Disclosure via External NTLM Authentication") )
                                if verbose_flag is True:
                                    print("        > " + host + " : SMTP NTLM Auth Info Disclosure : " + smtp_info)


    # Close output file
    outfile.close()   
    print("   [+] Done")                
    
# END Parse SMTP
########################################

########################################
# Parse SSH Issues
def parseSsh(INFILE, OUT_PRE, VERBOSE):

    # Issues Parsed (NSE Scripts):
    #   - Weak CBC, MAC, Key Exchange (ssh2-enum-algos)
    #   - SSH Version 1 Supported (sshv1)

    # SSH Weak CBC Ciphers Enabled; ID 70658
    ssh_weak_algos = [                  \
        '3des-cbc',                     \
        'aes128-cbc',                   \
        'aes192-cbc',                   \
        'aes256-cbc',                   \
        'blowfish-cbc',                 \
        'cast128-cbc',                  \
        'twofish-cbc',                  \
        'twofish128-cbc',               \
        'twofish192-cbc',               \
        'twofish256-cbc',               \
        'cast128-12-cbc@ssh.com',       \
        'des-cbc@ssh.com',              \
        'seed-cbc@ssh.com',             \
        'rijndael128-cbc',              \
        'rijndael192-cbc',              \
        'rijndael256-cbc',              \
        'rijndael-cbc@lysator.liu.se',  \
        'arcfour',                      \
        'arcfour128',                   \
        'arcfour256']

    # SSH Weak MAC Algorithms Enabled; ID 71049
    ssh_weak_macs = [                   \
        'hmac-md5',                     \
        'hmac-md5-96',                  \
        'hmac-sha1-96',                 \
        'hmac-sha2-256-96',             \
        'hmac-sha2-512-96']

    # SSH Weak Key Exchange Algorithms Enabled; ID 153953
    # Regex patterns added in this list only as the gss ciphers were listed with *.
    ssh_weak_kex = [                            \
        '^diffie-hellman-group-exchange-sha1$',   \
        '^diffie-hellman-group1-sha1$',           \
        '^gss-gex-sha1-',                       \
        '^gss-group1-sha1-',                    \
        '^gss-group14-sha1-',                   \
        '^rsa1024-sha1$']
    
    # SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795); ID 187315
    ssh_terrapin_algos = [
        'chacha20-poly1305@openssh.com', \
        'umac-64-etm@openssh.com',       \
        'umac-128-etm@openssh.com',      \
        'hmac-sha1-etm@openssh.com',     \
        'hmac-sha1-96-etm@openssh.com',  \
        'hmac-sha2-256-etm@openssh.com', \
        'hmac-sha2-512-etm@openssh.com']

    verbose_flag = VERBOSE
    infile = INFILE
    if OUT_PRE == None or OUT_PRE == "":
        ofp = ""
    else:
        ofp = OUT_PRE + "-"

    outfile = open((os.path.join(cwd, ofp + "reporting-ssh-issues_" + now + ".csv")), "w")
    writer = csv.writer(outfile, delimiter=',')
    writer.writerow( ('IP Address', 'Host Name', 'Service', 'Details', 'Vulnerability') )

    print("   [+] Parsing Nmap XML for SSH Issues.")

    tree = ET.ElementTree(file=infile)
    root = tree.getroot()

    for node in root.iter('host'):
        for address in node.iter('address'):
            host = address.get('addr')
            # Skip instances where a MAC address in address.get('addr')
            if re.match(ippat, host):
                for port in node.iter('port'):
                    portid = port.attrib.get('portid')
                    encAlgos = []
                    macAlgos = []
                    kexAlgos = []
                    terrapin = []

                    for script in node.iter('script'):
                        scriptid = script.attrib.get('id')

                        # Parse SSH Algos
                        if scriptid == "ssh2-enum-algos":
                            for table in script.iter('table'):
                                if table.attrib.get('key') == "encryption_algorithms":
                                    for algo in table.iter('elem'):
                                        if algo.text in ssh_weak_algos:
                                            encAlgos.append(algo.text)
                                        if algo.text in ssh_terrapin_algos:
                                            terrapin.append(algo.text)
                                if table.attrib.get('key') == "mac_algorithms":
                                    for algo in table.iter('elem'):
                                        if algo.text in ssh_weak_macs:
                                            macAlgos.append(algo.text)
                                        if algo.text in ssh_terrapin_algos:
                                                terrapin.append(algo.text)
                                if table.attrib.get('key') == "kex_algorithms":
                                    for algo in table.iter('elem'):
                                        if re.findall(r'|'.join(ssh_weak_kex),algo.text):
                                            kexAlgos.append(algo.text)

                            sortEnc=sorted(set(encAlgos))
                            sortMac=sorted(set(macAlgos))
                            sortKex=sorted(set(kexAlgos))
                            allAlgos = sortEnc + sortMac

                            sortTerrapin=sorted(set(terrapin))

                            if len(allAlgos) != 0:
                                writer.writerow( (host,"<HOSTNAME>","TCP%s (SSH)" % (portid),';;; '.join(allAlgos),"SSH Server Supports Weak Encryption") )
                                if verbose_flag is True:
                                    print("        > " + host + " TCP%s (SSH) " % (portid) + ";;; ".join(allAlgos))

                            if len(sortKex) != 0:
                                writer.writerow( (host,"<HOSTNAME>","TCP%s (SSH)" % (portid),';;; '.join(sortKex),"SSH Server Supports Weak Key Exchange Algorithms") )
                                if verbose_flag is True:
                                    print("        > " + host + " TCP%s (SSH) " % (portid) + ";;; ".join(sortKex))

                            if len(sortTerrapin) != 0:
                                writer.writerow ( (host,"<HOSTNAME>","TCP%s (SSH)" % (portid),';;; '.join(sortTerrapin),"SSH Prefix Truncation Weakness (Terrapin)") )

                        # Parse SSHv1
                        if scriptid == "sshv1": 
                            if script.text == "true":
                                writer.writerow( (host,"<HOSTNAME>","TCP%s (SSH)" % (portid),"Server Supports SSHv1","Server Supports SSHv1") )
                                if verbose_flag is True:
                                    print("        > " + host + " TCP%s (SSH) " % (portid) + "Server Supports SSHv1")

    outfile.close()
    print("   [+] Done")

# END Parse SSH Algos
########################################

########################################
# Banner
def banner():
    print(" + Nmap XML Parser Started + ")
########################################

########################################
# ---- Main ---- #

if __name__ == "__main__":
    p = argparse.ArgumentParser(description='Parse Nmap XML File from slober.sh and Output Evidence to CSV')
    p.add_argument('-i', help="Nmap XML Input File", required=True)
    p.add_argument('-w', help="Prepend Output File Identifier", required=False)
    p.add_argument('--mssql', dest='mssql_flag', help="Parse MSSQL Issues", action="store_true", required=False)
    p.add_argument('--mysql', dest='mysql_flag', help="Parse MySQL Issues", action="store_true", required=False)
    p.add_argument('--ntp', dest='ntp_flag', help="Parse NTP Clock Vars/Monlist", action="store_true", required=False)
    p.add_argument('--smb', dest='smb_flag', help="Parse SMB Issues", action="store_true", required=False)
    p.add_argument('--smtp', dest='smtp_flag', help="Parse SMTP Issues", action="store_true", required=False)
    #p.add_argument('--snmp', dest='snmp_flag', help="Parse SNMP Issues", action="store_true", required=False)
    p.add_argument('--ssh', dest='ssh_flag', help="Parse SSH Issues", action="store_true", required=False)
    p.add_argument('-v', help="Print Output to Console", action="store_true", required=False)
    p.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))

    args = p.parse_args()

    if (args.smb_flag + args.mssql_flag + args.ssh_flag + args.mysql_flag + args.ntp_flag + args.smtp_flag) != True:
        print("[!] Error. You must define something to parse.")
        p.print_help()
        sys.exit(1)
    
    if args.smb_flag is True:
        banner()
        parseSmb(args.i, args.w, args.v)

    if args.ssh_flag is True:
        banner()
        parseSsh(args.i, args.w, args.v)

    if args.mssql_flag is True:
        banner()
        parseMssql(args.i, args.w, args.v)

    if args.mysql_flag is True:
        banner()
        parseMysql(args.i, args.w, args.v)

    # if args.snmp_flag is True:
    #     banner()
    #     parseSnmp(args.i, args.w, args.v)

    if args.ntp_flag is True:
        banner()
        parseNtp(args.i, args.w, args.v)
    
    if args.smtp_flag is True:
        banner()
        parseSmtp(args.i, args.w, args.v)
    
   

# ------------------------------------
