"""
This is the manager application for the Atumsoft adapters
"""
from collections import defaultdict

import AtumsoftGeneric
import AtumsoftServer
import AtumsoftUtils
import threading
import Queue


class AtumsoftManager:
    def __init__(self, isVirtual=True, isHost=False):
        """
        This class manages either the one network adapter, or a collection of adapters
        :param isVirtual: determines whether to create a virtual adapter or use an existing one
        :param isHost: Host machines run an array of virtual adapters, client machines only run one adapter,
         either virtual or physical
        """
        if not isHost:
            self.tunTap = AtumsoftGeneric.AtumsoftGeneric(isVirtual)
        else:
            self.tunTap = AdapterDict()

        self.isHost = isHost
        self.infoQ = Queue.Queue()
        self._webServer = ListenThread(self.infoQ, isHost)

        self.findHosts()

    def findHosts(self):
        self._webServer.start()
        self._webServer.setDaemon(True)


class ListenThread(threading.Thread):
    def __init__(self, infoQ, persistent=False):
        super(ListenThread, self).__init__()
        self.persistent = persistent
        self.hostQ = infoQ
        self.routeDict = defaultdict(dict)
        self._activeHosts = False

    def run(self):
        AtumsoftServer.run()
        while 1:
            if not self._activeHosts or self.persistent:
                self._activeHosts = self.listen()


    def listen(self):
        hosts = AtumsoftUtils.findHosts(self.netIface, [self.gateway])
        if not hosts: return
        for host, info in hosts.iteritems():
            if info.get('address'):
                self.routeDict[host]['dstIP'] = info['address'].keys()[0]
                self.routeDict[host]['dstMAC'] = info['address'].values()[0]
        return True


class AdapterDict(dict):
    def __init__(self, *args, **kwargs):
        """
        This class functions as a collection of tuntap adapters for host machines
        """
        super(AdapterDict, self).__init__(*args, **kwargs)