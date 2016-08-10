import ast
import random
import requests
import json
import socket

import struct

import nmap
import os
import sys
import subprocess
import threading

#os specific imports:
try:
    import fcntl
except:
    pass


def listenForSever(info):
    # UDP server that responds to broadcast packets. Run this on the device attached to the instrument
    address = ('', 54545)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(address)

    print "Listening..."
    recv_data, addr = server_socket.recvfrom(2048)
    server_socket.sendto(str(info), addr)
    server_socket.close()
    return addr[0], ast.literal_eval(recv_data)


def findDevices(info):
    # UDP client that broadcasts to all of the devices, run this on the VM
    address = ('<broadcast>', 54545)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    client_socket.sendto(str(info), address)
    client_socket.settimeout(3)

    hostDict = {}
    while True:
        try:
            recv_data, addr = client_socket.recvfrom(2048)
            hostDict[addr[0]] = ast.literal_eval(recv_data)
        except socket.timeout:
            break
    client_socket.close()
    return hostDict


# # Code for posting to the webserver in a separate thread
# class POSTSession(threading.Thread):
#     def __init__(self, ip_address, inputQ):
#         super(POSTSession, self).__init__()
#
#         self._server_ip = ip_address
#         self.inputQ = inputQ
#
#     def run(self):
#         with requests.Session() as s:
#             while 1:
#                 if not self.inputQ: continue
#
#                 data = self.inputQ.get()
#                 try:
#                     r = s.post('http://%s:5000/add' % self._server_ip, data=json.dumps(str(data)))#.encode('string-escape'))
#                     if r.status_code != 200:
#                         print 'Server returned status: %s' % r.status_code
#                     else:
#                         print 'successfully sent 1 packet: length '+str(len(data))
#                 except requests.ConnectionError:
#                     print 'Connection error, please check connection to server'
#                 except UnicodeDecodeError:
#                     print '\n\ncan\'t decode: %s\n\n' % data
#
#
# def findHosts(adapterIP, gateWayIpList=None, iface=None):
#     """
#     if no interface is specified, scans the network for available servers on port 5000.
#     If an interface is specified, scans that interface for connected devices.
#     :param adapterIP: IP address of network adapter
#     :param gateWayIpList: List of network gateways to scan
#     :param iface: interface that devices are connected to
#     :return: dictionary of valid devices either on the network or connected to the interface
#     """
#     if not gateWayIpList:
#         gateWayIpList = [adapterIP]
#
#     if not type(gateWayIpList) == list:
#         gateWayIpList = list(gateWayIpList)
#
#     validHostDict = {}
#
#     for ip_address in gateWayIpList:
#         portScanner = nmap.PortScanner()
#         ipTuple = ip_address.split('.')
#         hostScan = '%s.%s.%s.%s' % (ipTuple[0], ipTuple[1], ipTuple[2], '0/24')
#
#         # need to scan differently if interface is specified just to find attached devices
#         if iface:
#             scanArgs = '-sP -e %s' % iface
#         else:
#             scanArgs = '-p 5000'
#
#         scan = portScanner.scan(hosts=hostScan, arguments=scanArgs)
#         for host in scan['scan']:
#             if host == adapterIP: continue
#             if not iface:
#                 if scan['scan'][host]['tcp'][5000]['state'] != 'open':
#                     continue
#                 # for some reason, macs have port 5000 open, so need to filter those
#                 if scan['scan'][host]['vendor'].get(scan['scan'][host]['addresses'].get('mac')) == 'Apple':
#                     continue
#                 addresses = findHostInfo(host)
#                 if not addresses: continue
#             if iface:
#                 addresses = {host : scan['scan'][host]['addresses']['mac']}
#             validHostDict[host] = {'address': addresses}
#
#     return validHostDict

def findHostInfo(hostIP):
    r = requests.get('http://%s:5000/getinfo' % hostIP)

    try:
        jsonDict = ast.literal_eval(r.json())
        return jsonDict
    except Exception, e:
        print e.message
        return None

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
    # return ''.join(map(lambda x: "%02x" % x, mac))
    return ''.join([chr(b) for b in mac]), ':'.join(['%02x' % (b) for b in mac])

def findGateWay():
    """
    finds the default gateway used by the system. Used for host scanning on the network
    """
    if 'linux' in sys.platform:
        command = 'route -n'
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output = process.communicate()[0]
        routeList = []

        # construct list of lists out of output
        for line in output.split('\n'):
            if line.lower() == 'kernel ip routing table': continue
            lineList = []
            for word in line.split(' '):
                if not word: continue  # skip multiple spaces
                lineList.append(word)
            routeList.append(lineList)

        # rotate routeList
        routeList = routeList[:-1]
        routeList = zip(*routeList[::-1])

        # Build dict out of list structure
        routeDict = {row[::-1][0]: row[::-1][1:] for row in routeList}

        ifaces = set([iface for iface in routeDict['Iface']])
        ipAddrs = [ipAddr for ipAddr in routeDict['Gateway'] if ipAddr != '0.0.0.0']
        return ipAddrs, list(ifaces)[0]

    elif 'win' in sys.platform:
        command = 'route print'
        proc = subprocess.Popen(command, stdout=subprocess.PIPE)
        output = proc.communicate()[0]
        routeList = []

        # construct list of output
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if not line.startswith('IPv4 Route Table'): continue
            index = i + 3

            while not lines[index].startswith('==='):
                lineList = []
                for word in lines[index].strip().split('  '):
                    if not word: continue
                    lineList.append(word.strip())
                index += 1
                routeList.append(lineList)

        # rotate routeList
        routeList = routeList[:-1]
        routeList = zip(*routeList[::-1])

        # Build dict out of list structure
        routeDict = {row[::-1][0]: row[::-1][1:] for row in routeList}

        # only care about routes of 0.0.0.0; filters info for the active iface
        gateWayIndex = 0
        for rowInfo, details in routeDict.copy().iteritems():
            for i, route in enumerate(details):
                if route == '0.0.0.0':
                    gateWayIndex = i

            routeDict[rowInfo] = details[gateWayIndex]

        gateWayIP = routeDict['Gateway']
        gatewayIfaceIP = routeDict['Interface']

        return gateWayIP, gatewayIfaceIP
# physical on ethernet port

def getIP(ifname=None):
    if 'linux' in sys.platform:
        if not ifname:
            ifaceList = os.listdir('/sys/class/net')

            def findIface(ifaceprefix):
                for iface in ifaceList:
                    if iface.startswith(ifaceprefix):
                        return iface
                return None

            #first find wireless adapters, then try ethernet (VM only probably)
            ifname = findIface('w')
            if not ifname:
                ifname = findIface('e')

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    elif 'win' in sys.platform:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("gmail.com", 80))
        ip= (s.getsockname()[0])
        s.close()
        return ip
        # return socket.gethostbyname(socket.gethostname())