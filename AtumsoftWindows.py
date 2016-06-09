from AtumsoftBase import *
from AtumsoftUtils import *

try:
    import pywintypes
    import win32event
    import binascii
    import _winreg as reg
    import win32file
except:
    pass

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

    def __init__(self,name='',isVirtual=True):
        if not isVirtual: # haven't implemented physical sniffing and injection in windows yet
            raise NotImplementedError

        self.TUN_IPv4_ADDRESS    = [192,168,2,131] #< The IPv4 address of the TUN interface.
        self.TUN_IPv4_NETWORK    = [192,168,2,0] #< The IPv4 address of the TUN interface's network.
        self.TUN_IPv4_NETMASK    = [255,255,255,0] #< The IPv4 netmask of the TUN interface.

        ## Key in the Windows registry where to find all network interfaces (don't change, this is always the same)
        self.ADAPTER_KEY         = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'

        ## Value of the ComponentId key in the registry corresponding to your TUN interface.
        self.TUNTAP_COMPONENT_ID = 'tap0901'
        self.TAP_IOCTL_SET_MEDIA_STATUS        = self.TAP_CONTROL_CODE( 6, 0)
        self.TAP_IOCTL_CONFIG_TUN              = self.TAP_CONTROL_CODE(10, 0)

        self._name = name
        self._ipAddress = '0.0.0.0'
        self._macAddress = None
        self._upStatus = False
        self._readThread = None
        self._writeThread = None

    def createTunTapAdapter(self, ipAddress, macAddress):
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
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.ADAPTER_KEY) as adapters:
            try:
                for i in xrange(10000):
                    key_name = reg.EnumKey(adapters, i)
                    with reg.OpenKey(adapters, key_name) as adapter:
                        try:
                            component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
                            if component_id == self.TUNTAP_COMPONENT_ID:
                                self._name = reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                        except WindowsError, err:
                            pass
            except WindowsError, err:
                pass

    def openTunTap(self):
        '''
        brief Open a TUN/TAP interface
        '''

        # retrieve the ComponentId from the TUN/TAP interface
        componentId = self.name
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
        raise NotImplementedError # closing virtual device at runtime not supported on windows yet

    def startRead(self, sender, senderArgs):
        pass

    def startWrite(self, writeQ):
        pass

    def stopWrite(self):
        pass

    def stopRead(self):
        pass

    # windows specific methods -----------------------------------------------------------------------------------------
    def CTL_CODE(self, device_type, function, method, access):
        return (device_type << 16) | (access << 14) | (function << 2) | method;

    def TAP_CONTROL_CODE(self, request, method):
        return self.CTL_CODE(34, request, method, 0)

"""
IP_ADDRESS = '192.168.50.62'
# try:
#     MAC_ADDR = getHwAddr('eth9')
# except IOError:
#     print 'error creating'
#     # os.system('ip link add name atum0 type dummy')
#     # os.system('ifconfig atum0 up arp')
#     # os.system('ifconfig atum0 192.168.2.135')


class SniffThread(threading.Thread):
    ETHERNET_MTU = 1500
    IPv6_HEADER_LENGTH = 40
    IPV6_SRC_INDEXES = [x for x in xrange(22, 38)]
    IPV6_DST_INDEXES = [x for x in xrange(38, 54)]
    IPV4_INDEXES = [x for x in xrange(26, 34)]
    ETH_INDEXES = [x for x in xrange(0, 12)]

    def __init__(self, tapDev=None, transmit=WindowsWriteThread):
        super(SniffThread, self).__init__()
        # store params
        self.tuntap = tapDev
        self.transmit = transmit

        # local variables
        self.goOn = True
        self.overlappedRx = pywintypes.OVERLAPPED()
        self.overlappedRx.hEvent = win32event.CreateEvent(None, 0, 0, None)

        # initialize parent
        threading.Thread.__init__(self)

        # give this thread a name
        self.name = 'readThread'

    def run(self):
        rxbuffer = win32file.AllocateReadBuffer(self.ETHERNET_MTU)
        while 1:
            # Test packet generation --------
            # p = Ether(dst='ac:18:26:4b:18:23') / IP() / 'Hello World'
            # self.process_packet(p)
            # time.sleep(2)
            # -------------------------------

            # sniff(iface='eth5', prn=self.process_packet)

            # buf = self.tap.read(self.tap.mtu)
            # thread.start_new_thread(POST, (buf, IP_ADDRESS))
            l, bytes = win32file.ReadFile(self.tuntap, rxbuffer, self.overlappedRx)
            win32event.WaitForSingleObject(self.overlappedRx.hEvent, win32event.INFINITE)
            self.overlappedRx.Offset = self.overlappedRx.Offset + len(bytes)

            # convert input from a string to a byte list
            p = [(ord(b)) for b in bytes]

            # parse received packet
            # p = p[:12] + p[16:20] + p[12:16] + p[20:]
            # pkt = p[:]
            if (p[0]&0xf0)==0x40:
                # IPv4

                # keep only IPv4 packet
                total_length = 256*p[2]+p[3]
                p = p[:total_length]
                self.process(p)

    def process(self, pkt):
        try:
            # don't replace broadcast packets
            broadcast = binascii.unhexlify('ff:ff:ff:ff:ff:ff'.replace(':', ''))
            broadcast = [(ord(c)) for c in broadcast]
            if broadcast == pkt[0:6]:
                print 'broadcast'

            # replace ether layer
            etherSrc = binascii.unhexlify('00:ff:c6:a8:79:4D'.replace(':', ''))
            etherDst = binascii.unhexlify('4e:e4:d0:38:a1:c5'.replace(':', ''))
            etherAddrs = [(ord(c)) for c in etherDst + etherSrc]
            for (index, replacement) in zip(self.ETH_INDEXES, etherAddrs):
                pkt[index] = replacement
            thread.start_new_thread(POST, (pkt, IP_ADDRESS))

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

    def process_packet(self, pkt):
        # return if no packet
        if not pkt: return
        if not Ether in pkt: return pkt

        if pkt[Ether].src == '4e:e4:d0:38:a1:c5':#'ac:18:26:4b:18:23':
            return

        # return unchanged packet if broadcast addr
        if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff':
            print 'broadcast'
            # pkt[Ether].src = 'f0:de:f1:0b:c3:84'
            #
            # if ARP in pkt:
            #     pkt[ARP].hwsrc = 'f0:de:f1:0b:c3:84'
            #     pkt[ARP].psrc = '192.168.2.134'
            # print 'broadcast'
        else:
            pkt[Ether].dst = '4e:e4:d0:38:a1:c5'#'ac:18:26:4b:18:23'
            # pkt[Ether].src = '52:33:b7:53:b6:80'
            if IP in pkt:
                pkt[IP].dst = '192.168.2.136'
                # pkt[IP].src = '192.168.2.135'


        pkt = [ord(c) for c in str(pkt)]
        thread.start_new_thread(POST, (pkt, IP_ADDRESS))


class WindowsWriteThread(threading.Thread):
    '''
    \brief Thread with periodically sends IPv4 and IPv6 echo requests.
    '''

    SLEEP_PERIOD   = 1

    def __init__(self,tuntap,inputq):

        # store params
        self.tuntap               = tuntap
        self.inputq               = inputq

        # local variables
        self.goOn                 = True
        self.createIPv6           = False
        self.overlappedTx         = pywintypes.OVERLAPPED()
        self.overlappedTx.hEvent  = win32event.CreateEvent(None, 0, 0, None)

        # initialize parent
        threading.Thread.__init__(self)

        # give this thread a name
        self.name                 = 'writeThread'

    def run(self):

        while self.goOn:

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

    #======================== public ==========================================

    def close(self):
        self.goOn = False

    def transmit(self,dataToTransmit,echo=True):
        # remove old headers
        # dataToTransmit = dataToTransmit[28:]
        MacAddrs = binascii.hexlify(''.join([chr(s) for s in dataToTransmit[:14]]))
        data  = ''.join([chr(b) for b in dataToTransmit])
        # data = Raw(b'%s' % data)
        # with open('test.log', 'a') as logfile:
        #     logfile.write('\n%s\n' % (MacAddrs))
        # data = IP()/UDP()/(b'%s' % data)
        # data = str(data)

        # write over tuntap interface

        win32file.WriteFile(self.tuntap, data, self.overlappedTx)
        win32event.WaitForSingleObject(self.overlappedTx.hEvent, win32event.INFINITE)
        self.overlappedTx.Offset = self.overlappedTx.Offset + len(data)

        # sendp(data, iface='eth9')
        """