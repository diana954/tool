from glob import glob
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
import nmap
import requests
from bs4 import BeautifulSoup
import socket
import threading
import iptc
from scapy.all import *

def parse_access():
    file_handle= open('logsFile' , 'r')
    list_lines = file_handle.readlines()
    list_output=[]
    for i in range(0,len(list_lines)):
        x=list_lines[i].split()
        if x[0] not in list_output:
            list_output.append(x[0])
    for line in list_lines:
        urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', line)
        if urls not in list_output:
            list_output.append(urls)
    for line in list_lines:
        method= re.findall('GET|POST', line)
        if method not in list_output:
            list_output.append(method)
    for line in list_lines:
        user_agent= re.findall('[a-zA-Z]+/[0-9].[0-9]', line)	
        if user_agent not in list_output:
            list_output.append(user_agent)

    print(list_output)
    

    f = open('logscheck.txt','w')
    for line in list_output:
        f.write(''.join(line))
    f.close()

def dir_monitor():
    def getHash():
        filenames = glob("dir1/*.txt")
        hash1 = {}
        for filename in filenames:
            with open(filename, 'rb') as inputfile:
                data = inputfile.read()
                hash1[ filename[5:] ] = hashlib.md5(data).hexdigest()
        return hash1

    hash1 = getHash()

    while True:
        time.sleep(10)
        hash2 = getHash()
        logs = {}
        for ha4 in hash2:
            if ha4 not in hash1.keys():
                logs[ha4] = "File Added"
        for ha4 in hash1:
            if ha4 not in hash2.keys():
                logs[ha4] = "File Deleted"
        for ha4 in hash1:
            if ha4 in hash2.keys() and hash1[ha4] not in hash2.values():
                logs[ha4] = "File Modified"
        hash1 = hash2
            
        f= open("/root/logs.txt" , 'a')
        for log in logs:
            f.write(log + ": " + logs[log]+"\n")
        f.close()
        
def webscraping():
    input_URL= input('Enter URL: ')
    URL = input_URL
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, 'html5lib')
    print(soup.prettify())
    x= soup.prettify()

    all_links=soup.find_all('a')
    for link in all_links:
        print(link.get("href"))

    all_links=soup.find_all('img')
    for link in all_links:
        print(link.get("src"))

    tags = [tag.name for tag in soup.find_all()]
    unq_tags = set(tags)
    print(unq_tags)

def range_scan():
    network_addr = input("enter the first three octets in network address:")
    net_octets = network_addr.split('.')
    splitter = '.'

    temp_addr = net_octets[0]+splitter+net_octets[1]+splitter+net_octets[2]+splitter
    start_addr = int(input("enter start host: "))
    end_addr = int(input("enter end host: "))

    t1= datetime.now()
    for i in range(start_addr,end_addr):
        cur_addr = temp_addr+str(i)
        command='ping -c 2 ' + cur_addr
        result= os.popen(command)
        for line in result.readlines():
            if (line.count("ttl")):
                print (cur_addr + "is live!")
                break
    t2 = datetime.now()
    print ("+++ scan completed in: " ,t2-t1, "+++")

def port_scan():

    remoteServer    = input("Enter a remote host to scan: ")
    remoteServerIP  = socket.gethostbyname(remoteServer)

    print ("-" * 60)
    print ("Please wait, scanning remote host", remoteServerIP)
    print ("-" * 60)

    t1 = datetime.now()
    x = []
    try:
        choice= int(input("enter 1 for TCP or 2 for UDP:"))
        if choice ==1 :
            for port in range(1,1025):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((remoteServerIP, port))
                if result == 0:
                    print ("Port {}: 	 Open".format(port))
                    x.append(int(port))
                sock.close()
        elif choice ==2:
            for port in range(1,1025):  
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                result = sock.connect_ex((remoteServerIP, port))
                if result == 0:
                    print ("Port {}: 	 Open".format(port))
                sock.close()
        x= [str(result) for result in x]
        x= ','.join(x)
        CMD = f"nmap -sC -sV -p {x} {remoteServerIP}"
        nmap_scan=os.popen(CMD)


    except KeyboardInterrupt:
        print ("You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        print ('Hostname could not be resolved. Exiting')
        sys.exit()

     #except socket.error:
      #  print ("Couldn't connect to server")
       # sys.exit()
    t2 = datetime.now()
    total =  t2 - t1
    print ('Scanning Completed in: ', total)

def reOpen(port):
    os.system("nc -nvlp " + str(port) + " &")
    os.system("clear")

def getUnknownOpenPorts():
    global myIP
    host = socket.gethostbyname(myIP)
    openPorts = []
    for port in range(1, 30000):
        if port not in wellknown and port < 30000:
            scannerTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)
            status = scannerTCP.connect_ex((host, port))
            if not status:
                openPorts.append(port) 
    for p in openPorts:
        os.system("nc -nvlp " + str(p) + " &")
        os.system("clear")   
    return openPorts

def blockIP(ip):
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.in_interface = "eth0"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    rule.src = ip  
    chain.insert_rule(rule)

    os.system(f"iptables -A OUTPUT -d {ip} -j DROP") 

def print_summary(pkt):
    global myIP
    global unKnown
    tcp_sport = ""

    if "IP" in pkt:
        ip_src=pkt['IP'].src
        ip_dst=pkt['IP'].dst

    if 'TCP' in pkt:
        tcp_sport=pkt['TCP'].sport

    if (pkt['IP'].src == myIP)  and tcp_sport in unKnown:
        blockIP(pkt['IP'].dst)
        reOpen(tcp_sport)
        print("Attack detected!")
        print(f"Blocking {pkt['IP'].dst} ...\nBlocked!\n")


def Monitor():
    sniff(filter="ip",prn=print_summary)
    sniff(filter="ip and host " + myIP, prn=print_summary)
wellknown = [1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080]
unKnown = []
def attack_prev():

    global myIP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    unKnown = getUnknownOpenPorts()

    if(len(unKnown)):
        print(f"Monitoring {myIP}....")
        Monitor()
    else:
        print("No Open ports were detected")

choice = input("Choose one of these: \n 1: Parse access.log file \n 2: Directory Monitoring \n 3: Nmap Scan \n 4: Attack Prevention \n 5: Web Scraping \n ")

if choice == "1":
    parse_access()
elif choice == "2":
    dir_monitor()
elif choice =="3":
    range_scan()
    port_scan()
elif choice =="4":
    attack_prev()
elif choice == "5":
    webscraping()
