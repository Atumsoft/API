from AtumsoftBase import *
from AtumsoftUtils import *

try:
    import ast
    from pytun import TunTapDevice, IFF_NO_PI, IFF_TAP

    import fcntl
    from scapy.all import *
    from scapy.layers.inet import IP
except:
    pass

class AtumsoftLinux(TunTapBase):
    platform = 'linux'

    # properties
    @property
    def ipAddress(self):
        return self._getIP()

    @property
    def macAddress(self):
        return self._getMac()

    @property
    def isUp(self):
        if self.isVirtual:
            return self._upStatus
        else:
            return None

    @property
    def name(self):
        return self._name

    # methods
    def __init__(self, name='', isVirtual=True):
        """
        :param name: name of interface
        :param isVirtual: specifies whether this code will be running on a virtual interface
        """

        self._ipAddress = None
        self._macAddress = None
        self._name = name
        self._upStatus = False
        self._readThread = None
        self._writeThread = None

        self.isVirtual = isVirtual

    def _getMac(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', self.name[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

    def _getIP(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', self.name[:15])
        )[20:24])

    def createTunTapAdapter(self, ipAddress='0.0.0.0', macAddress='\x4e\xe4\xd0\x38\xa1\xc5'):
        assert self.isVirtual
        self._ipAddress = ipAddress
        self._macAddress = macAddress
        self.tap = TunTapDevice(name=self.name, flags=(IFF_NO_PI|IFF_TAP))

        self.tap.addr = ipAddress
        self.tap.hwaddr = macAddress
        self.tap.mtu=1500

    def openTunTap(self):
        assert self.isVirtual
        self._upStatus = True
        self.tap.up()

    def startRead(self, sender=POST, senderArgs=('0.0.0.0',)):
        if self.isVirtual:
            assert self.isUp

        routeDict = {
            'srcIP' : self.ipAddress,
            'dstIP' : '0.0.0.0',
            'srcMAC': self.macAddress,
            'dstMAC': ''
        }
        self._readThread = LinuxSniffer(self.name, self.isVirtual, sender, senderArgs, routeDict)
        self._readThread.setDaemon(True)
        self._readThread.start()

    def startWrite(self, writeQ):
        if self.isVirtual:
            assert self.isUp
            writeIface = self.tap
        else:
            writeIface = self.name
        self._writeThread = LinuxWriter(writeIface,self.isVirtual,writeQ)
        self._writeThread.setDaemon(True)
        self._writeThread.start()

    def closeTunTap(self):
        assert self.isVirtual
        self._upStatus = False
        self.tap.down()

    def stopRead(self):
        self._readThread.close()

    def stopWrite(self):
        self._writeThread.close()


class LinuxSniffer(SniffBase):
    def __init__(self, iface, isVirtual, sender, senderArgs, routeDict={}):
        """
        :param iface: name of interface to sniff on
        :param isVirtual: boolean for whether this code will be acting on a virtual interface or a physical one
        :param sender: function to send sniffed packet across network
        :param senderArgs: tuple containing args for sender function
        :param routeDict: dictionary containing routing information (needs at minimum: srcIP, dstIP, srcMAC, and dstMAC)
        """
        super(LinuxSniffer, self).__init__()
        routes = [ # routes required for packet processing to be successful
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
        assert set(routes).issubset(set(self.routeDict.keys()))

    def run(self):
        while self.running:
            sniff(iface=self.name, prn=self.process)

    def process(self, pkt):
        # return if no packet
        if not pkt: return

        # return when sniffing a packet that was just injected
        if pkt[Ether].src == self.routeDict.get('dstMAC'): return

        # return if the packet originated from self and using a physical interface
        if not self.isVirtual:
            if pkt[Ether].src == self.routeDict.get('srcMAC'):
                print 'from self'
                return

        # return unchanged packet if broadcast addr
        if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff':
            print 'broadcast'

        else:
            # change ether layer dst
            pkt[Ether].dst = self.routeDict.get('dstMAC')
            if IP in pkt: # change IP layer dst if the layer is present
                pkt[IP].dst = self.routeDict.get('dstIP')

        # convert packet from raw byte string into an array of byte values to be safely transmitted over the network
        pkt = [ord(c) for c in str(pkt)]
        self.send(pkt)

    def send(self, pkt):
        thread.start_new_thread(self.sendFunc, ((pkt,)+self.sendArgs))

    def close(self):
        self.running = False


class LinuxWriter(WriteBase):
    def __init__(self, iface, isVirtual, writeQ):
        """
        :param iface: interface to write to
        :param isVirtual: specifies whether interface is physical or virtual
        :param writeQ: input Queue object to get packets from
        """
        super(LinuxWriter, self).__init__()
        self.iface = iface
        self.running = True
        self.isVirtual = isVirtual
        self.writeQ = writeQ

    def run(self):
        while self.running:
            if not self.writeQ: continue

            # weird evals for stringized list from json
            pkt = self.writeQ.get()
            while type(pkt) == str:
                pkt = ast.literal_eval(pkt)

            # send packet over either virtual adapter or physical network
            if self.isVirtual:
                self.iface.write(pkt)
            else:
                pkt = Raw(pkt)
                sendp(pkt, iface=self.iface)

    def close(self):
        self.running = False