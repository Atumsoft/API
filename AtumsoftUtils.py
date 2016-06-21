import random
import requests
import json
import nmap
import os
import sys
import subprocess


# Code for posting to the webserver in a separate thread
def POST(data, ip_address):
    try:
        r = requests.post('http://%s:5000/add' % ip_address, data=json.dumps(str(data)))#.encode('string-escape'))
        if r.status_code != 200:
            print 'Server returned status: %s' % r.status_code
        else:
            print 'successfully sent 1 packet: length '+str(len(data))
    except requests.ConnectionError:
        print 'Connection error, please check connection to server'
    except UnicodeDecodeError:
        print '\n\ncan\'t decode: %s\n\n' % data

# code for scanning the network for other available servers
def findHosts(localhost, ip_addressList):
    if not type(ip_addressList) == list:
        ip_addressList = list(ip_addressList)

    validHostDict = {}

    for ip_address in ip_addressList:
        portScanner = nmap.PortScanner()
        ipTuple = ip_address.split('.')
        hostScan = '%s.%s.%s.%s' % (ipTuple[0], ipTuple[1], ipTuple[2], '0/24')
        scan = portScanner.scan(hosts=hostScan, arguments='-p 5000')
        for host in scan['scan']:
            if host == localhost: continue
            if scan['scan'][host]['tcp'][5000]['state'] != 'open':
                continue
            # for some reason, macs have port 5000 open, so need to filter those
            if scan['scan'][host]['vendor'].get(scan['scan'][host]['addresses'].get('mac')) == 'Apple':
                continue
            validHostDict[host] = {'address': findHostInfo(host)}

    print validHostDict
    return validHostDict

def findHostInfo(hostIP):
    r = requests.get('http://%s:5000/getinfo' % hostIP)

    try:
        jsonDict = r.json()
        return jsonDict
    except:
        pass


# misc
def formatByteList(byteList):
    '''
    \brief Format a byte list into a string, which can then be printed.

    For example:
       [0x00,0x11,0x22] -> '(3 bytes) 001122'

    \param[in] byteList A list of integer, each representing a byte.

    \return A string representing the byte list.
    '''
    return '({0} bytes) {1}'.format(len(byteList),''.join(['%02x'%b for b in byteList]))

def carry_around_add(a, b):
    '''
    \brief Helper function for checksum calculation.
    '''
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(byteList):
    '''
    \brief Calculate the checksum over a byte list.

    This is the checksum calculation used in e.g. the ICMPv6 header.

    \return The checksum, a 2-byte integer.
    '''
    s = 0
    for i in range(0, len(byteList), 2):
        w = byteList[i] + (byteList[i+1] << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff


def randomMAC():
    mac = [ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))