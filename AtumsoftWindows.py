from AtumsoftBase import *
from AtumsoftUtils import *
import AtumsoftServer
import sys

try:
    import pywintypes
    import win32event
    import binascii
    import _winreg as reg
    import win32file
    import thread
except Exception, e:
    if sys.platform == 'win32':
        print e.message

import os
import subprocess
import time
from collections import defaultdict

ADD_TAP_DEV_COMMAND = '"C:\\Program Files\\TAP-Windows\\bin\\devcon.exe" install "C:\\Program Files\\TAP-Windows\\driver\\OemWin2k.inf" tap0901'
REMOVE_ALL_TAP_COMMAND = '"C:\\Program Files\\TAP-Windows\\bin\\devcon.exe" remove tap0901'

class AtumsoftWindows(TunTapBase):
    platform = 'win32'

    @property
    def ipAddress(self):
        return self._ipAddress

    @property
    def macAddress(self):
        return self._macAddress

    @property
    def isUp(self):
        return self._upStatus

    @property
    def name(self):
        return self._name

    @property
    def gateway(self):
        return self._gateWay

    @property
    def activeHosts(self):
        return self._activeHosts

    def __init__(self,isVirtual=True,iface=None):
        if not isVirtual: # haven't implemented physical sniffing and injection in windows yet
            raise NotImplementedError

        # Key in the Windows registry where to find all network interfaces (don't change, this is always the same)
        self.ADAPTER_KEY         = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'

        # Value of the ComponentId key in the registry corresponding to your TUN interface (don't change, this is always the same).
        self.TUNTAP_COMPONENT_ID = 'tap0901'
        self.TAP_IOCTL_SET_MEDIA_STATUS        = self.TAP_CONTROL_CODE( 6, 0)
        self.TAP_IOCTL_CONFIG_TUN              = self.TAP_CONTROL_CODE(10, 0)

        self.isVirtual = isVirtual
        self._name = ''
        self._ipAddress = ''
        self._macAddress = None
        self._upStatus = False
        self._readThread = None
        self._writeThread = None
        self._activeHosts = None
        self._runningServer = False
        self._listening = not self._activeHosts
        self.routeDict = defaultdict(dict)
        self._existing = False

    def __del__(self):
        print 'shutting down...'

        def tryfunc(func):
            try:
                func()
            except Exception, e:
                print e.message  # variables already closed possibly

        tryfunc(self.closeTunTap)
        tryfunc(self.stopCapture)
        tryfunc(AtumsoftServer.shutdown_server)

    def listen(self):
        thread.start_new(AtumsoftServer.run, tuple())
        self._runningServer = True
        while not self._activeHosts:
            time.sleep(2)
            self._activeHosts = self._findHosts(self.netIface, [self.gateway])
            self._listening = not self._activeHosts

        for host, info in self._activeHosts.iteritems():
            if info.get('address'):
                self.routeDict[host]['dstIP'] = info['address'].keys()[0]
                self.routeDict[host]['dstMAC'] = info['address'].values()[0]
                print self.routeDict

    def startCapture(self, sender=POST, senderArgs='', writeQ=AtumsoftServer.inputQ):
        if not self._activeHosts:
            self.listen()

        if not self._runningServer:
            thread.start_new_thread(AtumsoftServer.run, tuple())

        hosts = self.routeDict.keys()[0]
        print hosts
        self._startRead(sender, (hosts,))
        self._startWrite(writeQ)
        print 'connection made! capturing...'
        while 1:
            # time.sleep(10)
            # proc = subprocess.Popen('ping %s' % '192.168.2.133', stdout=subprocess.PIPE)
            # output = proc.communicate()[0]
            # print output
            pass
    def stopCapture(self):
        self._stopRead()
        self._stopWrite()

    def createTunTapAdapter(self, name='', ipAddress='', macAddress='', existing=False):
        '''
        Retrieve the instance ID of the TUN/TAP interface from the Windows
            registry,

        This function loops through all the sub-entries at the following location
        in the Windows registry: reg.HKEY_LOCAL_MACHINE, ADAPTER_KEY

        It looks for one which has the 'ComponentId' key set to
        TUNTAP_COMPONENT_ID, and returns the value of the 'NetCfgInstanceId' key.

        return The 'ComponentId' associated with the TUN/TAP interface, a string
            of the form "{A9A413D7-4D1C-47BA-A3A9-92F091828881}".
        '''
        assert self.isVirtual # can't create a device if we are using a physical interface
        self._existing = existing
        if not existing:
            proc = subprocess.Popen(ADD_TAP_DEV_COMMAND, stdout=subprocess.PIPE)
            print proc.communicate()[0]

            time.sleep(3) # for some reason, need to give windows a second before device shows up in ipconfig
        info = self._getAdapterInfo('TAP-Windows')
        origname = info.keys()[0]

        # command to rename iface
        if name:
            proc = subprocess.Popen('netsh interface set interface name="%s" newname="%s"' % (origname, name), stdout=subprocess.PIPE)
            output = proc.communicate()[0]
            if not output.strip():
                print 'successfully renamed %s to: %s' % (origname, name)
                self._name = name
                info[self._name] = info.pop(origname)
            else:
                print output.strip()
                raise WindowsError
        else:
            self._name = origname

        # assign ip address to interface
        if ipAddress:
            proc = subprocess.Popen('netsh interface ip set address "%s" static %s 255.255.255.0 %s' % (self._name, ipAddress, '192.168.2.101'), stdout=subprocess.PIPE)
            output = proc.communicate()[0]
            if not output.strip():
                print 'successfully changed ip address to %s' % ipAddress
                self._ipAddress = ipAddress
            else:
                print output.strip()
                raise WindowsError
        else:
            print 'Please provide IP address for adapter!'
            return

        # get mac address from interface
        if not macAddress:
            self._macAddress = info[self._name]['Physical Address'].replace('-',':').lower()
            print 'mac address is: %s' % self._macAddress
        else:
            raise NotImplementedError('Manual mac setting not supported on Windows yet')

        VIRTUAL_ADAPTER_DICT[self._ipAddress] = self._macAddress

        # create connection to adapter
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.ADAPTER_KEY) as adapters:
            try:
                for i in xrange(10000):
                    key_name = reg.EnumKey(adapters, i)
                    with reg.OpenKey(adapters, key_name) as adapter:
                        try:
                            component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
                            if component_id == self.TUNTAP_COMPONENT_ID:
                                self._id = reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                        except WindowsError, err:
                            pass
            except WindowsError, err:
                pass

    def openTunTap(self):
        '''
        brief Open a TUN/TAP interface
        '''

        # retrieve the ComponentId from the TUN/TAP interface
        componentId = self._id
        print('componentId = {0}'.format(componentId))

        # create a win32file for manipulating the TUN/TAP interface
        self.tuntap = win32file.CreateFile(
            r'\\.\Global\%s.tap' % componentId,
            win32file.GENERIC_READ    | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
            None
        )
        print('tuntap      = {0}'.format(self.tuntap.handle))

        # have Windows consider the interface now connected
        win32file.DeviceIoControl(
            self.tuntap,
            self.TAP_IOCTL_SET_MEDIA_STATUS,
            '\x01\x00\x00\x00',
            None
        )
        self._upStatus = True

    def closeTunTap(self):
        assert self.isVirtual
        if self._existing: return
        self._upStatus = False
        proc = subprocess.Popen(REMOVE_ALL_TAP_COMMAND, stdout=subprocess.PIPE)
        print proc.communicate()[0]

    def _findHosts(self, *args):
        return findHosts(*args)

    def _getMac(self):
        return self._macAddress

    def _startRead(self, sender, senderArgs):
        """
        starts reading from the adapter
        :param sender: function to handle sending packets over network
        :param senderArgs: args for sender function
        """
        if self.isVirtual:
            assert self.isUp

        hostRouteDict = self.routeDict[self.routeDict.keys()[0]]

        hostRouteDict.update({
            'srcIP': self.ipAddress,
            'srcMAC': self.macAddress,
        })
        self._readThread = WindowsSniffer(self.tuntap, self.isVirtual, sender, senderArgs, hostRouteDict)
        self._readThread.setDaemon(True)
        self._readThread.start()

    def _startWrite(self, writeQ):
        if self.isVirtual:
            assert self.isUp
            writeIface = self.tuntap
        else:
            writeIface = self.name
        self._writeThread = WindowsWriter(writeIface, self.isVirtual, writeQ)
        self._writeThread.setDaemon(True)
        self._writeThread.start()

    def _stopWrite(self):
        self._writeThread.close()

    def _stopRead(self):
        self._readThread.close()

    # windows specific methods -----------------------------------------------------------------------------------------
    def CTL_CODE(self, device_type, function, method, access):
        return (device_type << 16) | (access << 14) | (function << 2) | method;

    def TAP_CONTROL_CODE(self, request, method):
        return self.CTL_CODE(34, request, method, 0)

    def _getAdapterInfo(self, Description=''):
        """
        parses output of ipconfig /all into a dictionary containing info of all ethernet adapters attached to computer
        then removes all ethernet devices that are not TAP_Win devices created by this code
        :return: dictionary containing details about TAP-Win devices on this computer
        """
        proc = subprocess.Popen('ipconfig /all', stdout=subprocess.PIPE)
        stdout = proc.communicate()[0]
        lines = stdout.split('\n')
        adapterDetailDict = defaultdict(dict)

        for i, line in enumerate(lines):
            if line.startswith('Ethernet'): # will be ethernet device
                index = i+2
                while lines[index][0].isspace(): # indented by spaces
                    if not lines[index].strip():
                        index += 1
                        continue
                    try:
                        title, descr = lines[index].split(':', 1)
                        adapterDetailDict[line.replace('Ethernet adapter', '').replace(':', '').strip()].update( {title.replace('.', '').strip(): descr.strip()} )
                    except ValueError:
                        print lines[index]
                    index += 1

        if Description:
            # great! now remove all the adapters that we don't want
            for name, details in adapterDetailDict.copy().iteritems():
                if not Description in details['Description']:
                    del adapterDetailDict[name]
        return adapterDetailDict


class WindowsSniffer(SniffBase):
    ETHERNET_MTU = 1500
    IPv6_HEADER_LENGTH = 40
    IPV6_SRC_INDEXES = [x for x in xrange(22, 38)]
    IPV6_DST_INDEXES = [x for x in xrange(38, 54)]
    IPV4_INDEXES = [x for x in xrange(26, 34)]
    ETH_INDEXES = [x for x in xrange(0, 12)]

    def __init__(self, iface, isVirtual, sender, senderArgs, routeDict={}):
        super(WindowsSniffer, self).__init__()

        routes = [  # routes required for packet processing to be successful
            'srcIP',
            'dstIP',
            'srcMAC',
            'dstMAC',
        ]

        self.name = iface
        self.running = True
        self.isVirtual = isVirtual
        self.routeDict = routeDict
        self.sendFunc = sender
        self.sendArgs = senderArgs
        self.tuntap = iface

        self.running = True
        self.overlappedRx = pywintypes.OVERLAPPED()
        self.overlappedRx.hEvent = win32event.CreateEvent(None, 0, 0, None)

        try:
            assert set(routes).issubset(set(self.routeDict.keys()))
            print self.routeDict
        except AssertionError:
            print self.routeDict

    def run(self):
        rxbuffer = win32file.AllocateReadBuffer(self.ETHERNET_MTU)
        while self.running:
            try:
                # Test packet generation --------
                # p = Ether(dst='ac:18:26:4b:18:23') / IP() / 'Hello World'
                # self.process_packet(p)
                # time.sleep(2)
                # -------------------------------

                # sniff(iface='eth5', prn=self.process_packet)

                l, p = win32file.ReadFile(self.tuntap, rxbuffer, self.overlappedRx)
                win32event.WaitForSingleObject(self.overlappedRx.hEvent, win32event.INFINITE)
                self.overlappedRx.Offset = self.overlappedRx.Offset + len(p)
                # convert input from a string to a byte list
                p = [(ord(b)) for b in p]

                # parse received packet
                # p = p[:12] + p[16:20] + p[12:16] + p[20:]
                # pkt = p[:]
                if (p[14] & 0xf0) == 0x40:
                    # IPv4
                    # keep only IPv4 packet
                    total_length = (256 * p[16] + p[17]) + 14
                    p = p[:total_length]
                    self.process(p)
                elif (p[14] & 0xf0) == 0:
                    # ARP packet
                    p = p[:42]
                    self.process(p)
                else: print p[14] & 0xf0
                # l, p = win32file.ReadFile(self.tuntap, rxbuffer, self.overlappedRx)
                # p = p[:12] + p[16:20] + p[12:16] + p[20:]
                # p = [(ord(b)) for b in p]
                # self.process(p)
            except Exception, e:
                print e.message

    def process(self, pkt):
        try:
            # don't replace broadcast packets
            broadcast = binascii.unhexlify('ff:ff:ff:ff:ff:ff'.replace(':', ''))
            broadcast = [(ord(c)) for c in broadcast]
            if broadcast == pkt[0:6]:
                print 'broadcast'

            else:
                # replace ether layer
                etherSrc = binascii.unhexlify(self.routeDict['srcMAC'].replace(':', ''))
                etherDst = binascii.unhexlify(self.routeDict['dstMAC'].replace(':', ''))
                etherAddrs = [(ord(c)) for c in etherDst + etherSrc]
                for (index, replacement) in zip(self.ETH_INDEXES, etherAddrs):
                    pkt[index] = replacement

            self.post(pkt)
            # if  hex(pkt[14]) == '0x45': # ipv4 packet
            #     ipSrc =socket.inet_aton('169.254.11.86')
            #     ipDst = socket.inet_aton('169.254.11.85')
            #     ipAddrs = [(ord(c)) for c in ipSrc+ipDst]
            #     for (index, replacement) in zip(self.IPV4_INDEXES, ipAddrs):
            #         pkt[index] = replacement
            #
            # elif hex(pkt[14]) == '0x60': # ipv6 packet:
            #
            #     # Convert and replace ipv6 addresses
            #     ipv6Src = ipaddr.IPv6Address('fe80::f2de:f1ff:fe0b:c384').exploded.replace(':','')
            #     ipv6SrcHex = ''
            #     for (char1, char2) in zip(ipv6Src[0::2], ipv6Src[1::2]):
            #         ipv6SrcHex += chr(int(char1+char2, 16))
            #     ipv6SrcHex = [(ord(c)) for c in ipv6SrcHex]
            #     for (index, replacement) in zip(self.IPV6_SRC_INDEXES, ipv6SrcHex):
            #         pkt[index] = replacement
            #
            #     ipv6Dst = ipaddr.IPv6Address('fe80::ae18:26ff:fe4b:1823').exploded.replace(':','')
            #     ipv6DstHex = ''
            #     for (char1, char2) in zip(ipv6Dst[0::2], ipv6Dst[1::2]):
            #         ipv6DstHex += chr(int(char1 + char2, 16))
            #     ipv6DstHex = [(ord(c)) for c in ipv6DstHex]
            #     for (index, replacement) in zip(self.IPV6_DST_INDEXES, ipv6DstHex):
            #         pkt[index] = replacement
        except Exception, e:
            print e.message

    def post(self, pkt):
        thread.start_new_thread(self.sendFunc, ((pkt,) + self.sendArgs))

    def close(self):
        self.running = False

class WindowsWriter(WriteBase):
    SLEEP_PERIOD = 1

    def __init__(self, iface, isVirtual, writeQ):
        super(WindowsWriter, self).__init__()

        self.overlappedTx = pywintypes.OVERLAPPED()
        self.overlappedTx.hEvent = win32event.CreateEvent(None, 0, 0, None)
        self.tuntap = iface
        self.inputq = writeQ
        self.running = True

    def run(self):

        while self.running:
            try:

                # # sleep a bit
                # time.sleep(self.SLEEP_PERIOD)
                #
                # # create an echo request
                # dataToTransmit = self._createEchoRequest()

                if not self.inputq:
                    pass
                    # time.sleep(self.SLEEP_PERIOD)
                    # dataToTransmit = self._createEchoRequest()
                else:

                    # need to fix this...
                    dataToTransmit = ast.literal_eval(ast.literal_eval(self.inputq.get()))

                    # remove 14 byte header that was added
                    dataToTransmit = dataToTransmit
                    # print 'Packet: %s' % dataToTransmit

                    # with open('testfile.txt', 'a+') as outfile:
                    #     outfile.write( str(hexdump(''.join([chr(b) for b in dataToTransmit]))) )
                    #     outfile.write( '\n\n\n' )

                    # transmit
                    self.transmit(dataToTransmit)
            except Exception, e:
                print e.message

                # ======================== public ==========================================

    def close(self):
        self.running = False

    def transmit(self, dataToTransmit, echo=True):
        # remove old headers
        # dataToTransmit = dataToTransmit[28:]
        MacAddrs = binascii.hexlify(''.join([chr(s) for s in dataToTransmit[:14]]))
        data = ''.join([chr(b) for b in dataToTransmit])
        # data = Raw(b'%s' % data)
        # with open('test.log', 'a') as logfile:
        #     logfile.write('\n%s\n' % (MacAddrs))
        # data = IP()/UDP()/(b'%s' % data)
        # data = str(data)

        # write over tuntap interface
        win32file.WriteFile(self.tuntap, data, self.overlappedTx)
        win32event.WaitForSingleObject(self.overlappedTx.hEvent, win32event.INFINITE)
        self.overlappedTx.Offset = self.overlappedTx.Offset + len(data)
