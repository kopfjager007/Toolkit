#!/usr/bin/env python3
# Author: Aaron Lesmeister
# Purpose: A quick/very dirty script to run zookeeper commands to gather info.
# Date: 2022-09-21

import sys
import socket
import argparse
import os

__version__ = "1.0.0"

# Enumeration
def enum(target, port):
    buff = 2048
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Target " + target + " Port {}".format(str(port) ) )
    print("[+] Enumerating ZooKeper on " + target)

    # Run Commands
    # Srvr
    print("[*] Server Details:")
    try:
        # When testing it seemed ZK would terminate the connection after a command was sent and
        #  not allow additional commands over the same socket, so i'm connecting for each command.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.send("srvr\r".encode('utf-8'))
        data = s.recv(buff)
        print(data.decode())
        print("")
        s.close()
    except Exception as e:
        print("[!] Could not get server details ('srvr')")
        print( "EXCEPTION: {}".format(str(e) ) )
    # Envi
    print("[*] Serving Environment Details:")
    try:
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect((target, port))
        s1.send("envi\r".encode('utf-8'))
        data = s1.recv(buff)
        print(data.decode())
        print("")
        s1.close()
    except Exception as e:
        print("[!] Could not get environment details ('envi')")
        print( "EXCEPTION: {}".format(str(e) ) )
    # Conf
    print("[*] Configuration: ")
    try:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.connect((target, port))
        s2.send("conf\r".encode('utf-8'))
        data = s2.recv(buff)
        print(data.decode())
        print("")
        s2.close()
    except Exception as e:
        print("[!] Could not get configuration details ('conf')")
        print( "EXCEPTION: {}".format(str(e) ) )
    # Cons
    print("[*] Connection/Session Details for Clients: ")
    try:
        s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s3.connect((target, port))
        s3.send("cons\r".encode('utf-8'))
        data = s3.recv(buff)
        print(data.decode())
        print("")
        s3.close()
    except Exception as e:
        print("[!] Could not get client connection/session details ('cons')")
        print( "EXCEPTION: {}".format(str(e) ) )
    # Dump
    print("[*] Outstanding Sessions & Ephemeral Nodes:")
    try:
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.connect((target, port))
        s4.send("dump\r".encode('utf-8'))
        data = s4.recv(buff)
        print(data.decode())
        print("")
        s4.close()
    except Exception as e:
        print("[!] Could not get outstanding sessions or ephemeral nodes('dump')")
        print( "EXCEPTION: {}".format(str(e) ) )
    # Wchs
    print("[*] Brief Info for Watches for the Server: ")
    try:
        s5 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s5.connect((target, port))
        s5.send("wchs\r".encode('utf-8'))
        data = s5.recv(buff)
        print(data.decode())
        print("")
        s5.close()
    except Exception as e:
        print("[!] Could not get watches information('wchs')")
        print( "EXCEPTION: {}".format(str(e) ) )

if __name__ == "__main__":
	p = argparse.ArgumentParser(description='Enumerate Information from Zookeeper Instances')
	p.add_argument('--ip', help="Target IP Address", dest='target', required=True)
	p.add_argument('--port', type=int, help="Target Port (default: 2181)", dest='port', default='2181', required=False)
	p.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))

	args = p.parse_args()

	enum(args.target, args.port)
