import thread
import time
from AtumsoftBase import *
from AtumsoftUtils import *
import AtumsoftServer
import ast
from collections import defaultdict


try:
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
        return getIP(self.networkIface)

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

    @property
    def gateway(self):
        return self._gateway

    @property
    def activeHosts(self):
        return self._activeHosts

    # methods
    def __init__(self, isVirtual=True, iface=None):
        """
        :param isVirtual: specifies whether this code will be running on a virtual interface
        """

        self._ipAddress = None
        self._macAddress = None
        self._name = None
        self._upStatus = False
        self._readThread = None
        self._writeThread = None
        self._activeHosts = None
        self._listening = not self.activeHosts
        self._runningServer = False
        self._gateway, self.networkIface = findGateWay()

        self.isVirtual = isVirtual
        self.routeDict = defaultdict(dict) # k: ip address of host v: dict of ip and mac of all network adapters on host

        # if attached to a physical interface, some additional setup is needed
        if not isVirtual:
            self._name = iface
            print 'scanning for devices...'
            connectedDev = None
            while not connectedDev:
                try:
                    connectedDev = findHosts(getIP(iface), iface=iface)
                    print connectedDev
                except IOError:
                    print 'please set IP address for interface first'
                    time.sleep(5)
            connectedDevIp = connectedDev.keys()[0]
            connectedDevMAC = connectedDev[connectedDevIp]['address'][connectedDevIp]
            VIRTUAL_ADAPTER_DICT[connectedDevIp] = connectedDevMAC
            print VIRTUAL_ADAPTER_DICT

    def __del__(self):
        print 'shutting down...'
        def tryfunc(func):
            try:
                func()
            except Exception, e:
                print e.message # variables already closed possibly

        if self.isVirtual:
            tryfunc(self.closeTunTap)
            tryfunc(self.stopCapture)
        tryfunc(AtumsoftServer.shutdown_server)

    def _findHosts(self):
        return findHosts(getIP(self.networkIface))

    def _getMac(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', self.name[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

    def _startRead(self, hostIP=''):
        if self.isVirtual:
            assert self.isUp

        hostRouteDict = self.routeDict[self.routeDict.keys()[0]]

        hostRouteDict.update({
            'srcIP' : self.ipAddress,
            'srcMAC': self.macAddress,
        })
        self._readThread = LinuxSniffer(self.name, self.isVirtual, hostIP, hostRouteDict)
        self._readThread.setDaemon(True)
        self._readThread.start()

    def _startWrite(self, writeQ):
        if self.isVirtual:
            assert self.isUp
            writeIface = self.tap
        else:
            writeIface = self.name
        self._writeThread = LinuxWriter(writeIface,self.isVirtual,writeQ)
        self._writeThread.setDaemon(True)
        self._writeThread.start()

    def _stopRead(self):
        self._readThread.close()

    def _stopWrite(self):
        self._writeThread.close()

    def listen(self):
        print 'no hosts found, listening...'
        thread.start_new_thread(AtumsoftServer.run, tuple())
        self._runningServer = True
        self._listening = True
        while self._listening:
            time.sleep(2)
            # self._activeHosts = self._findHosts()
            self._listening = not AtumsoftServer.hostInfoDict

        print 'connection made!\n%s' % AtumsoftServer.hostInfoDict

        for host, info in AtumsoftServer.hostInfoDict.iteritems():
            if info.get('address'):
                self.routeDict[host]['dstIP'] = info['address'].keys()[0]
                self.routeDict[host]['dstMAC'] = info['address'].values()[0]
                print self.routeDict

    def createTunTapAdapter(self,name, ipAddress, macAddress=None, existing=False):
        """
        :param name: name of interface
        :param ipAddress: ipaddr to assign to interface
        :param macAddress: mac addr to assign to interface
        """
        assert self.isVirtual
        if not ipAddress: raise PropertyNotDefinedException # TODO: generate unique IP based on subnet used
        self._ipAddress = ipAddress

        if not macAddress: # generate random mac if not given
            macAddress, readableMac = randomMAC()
        self._macAddress = macAddress
        self._name = name
        VIRTUAL_ADAPTER_DICT[ipAddress] = readableMac
        self.tap = TunTapDevice(name=name, flags=(IFF_NO_PI|IFF_TAP))

        self.tap.addr = ipAddress
        self.tap.hwaddr = macAddress
        self.tap.mtu=1500
        print 'successfully created %s at:\n ip:%s\tmac:%s' % (self._name, ipAddress, readableMac)

    def openTunTap(self):
        assert self.isVirtual
        self._upStatus = True
        self.tap.up()

    def closeTunTap(self):
        assert self.isVirtual
        self._upStatus = False
        self.tap.down()

    def startCapture(self, hostIP='', writeQ=AtumsoftServer.inputQ):
        """
        Helper function for starting read/write ops
        :param sender: function for how to send read packets over network
        :param senderArgs: Arguments for sender function
        :param writeQ: Queue.Queue object where packets to be written are placed into
        """
        if not self.activeHosts: self.listen()
        if not self._runningServer:
            thread.start_new_thread(AtumsoftServer.run, tuple())

        hosts = self.routeDict.keys() # TODO: support more than one host
        self._startRead(hosts[0])
        self._startWrite(writeQ)
        print 'connection made! capturing...'
        while 1: 
            pass

    def stopCapture(self):
        self._stopRead()
        self._stopWrite()


class LinuxSniffer(SniffBase):
    def __init__(self, iface, isVirtual, senderArgs, routeDict={}):
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
        self.sendArgs = senderArgs
        self.postQ = AtumsoftServer.outputQ

        try:
            assert set(routes).issubset(set(self.routeDict.keys()))
            print self.routeDict
        except AssertionError:
            print self.routeDict

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
        try:
            pkt = [ord(c) for c in str(pkt)]
            self.postQ.put(pkt)
        except Exception, e:
            print e.message
            print 'error processing packet from %s' % self.name

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

            pkt = ''.join([chr(b) for b in pkt])

            # send packet over either virtual adapter or physical network
            if self.isVirtual:
                self.iface.write(pkt)
            else:
                pkt = Raw(pkt)
                sendp(pkt, iface=self.iface)

    def close(self):
        self.running = False