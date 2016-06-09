from abc import ABCMeta, abstractmethod, abstractproperty
import threading


class TunTapBase(object):
    """
    Superclass of all tuntap implementations. Aims to be agnostic for all possible platforms.
    """
    __metaclass__ = ABCMeta

    # properties
    @abstractproperty
    def ipAddress(self):
        pass

    def macAddress(self):
        pass

    @abstractproperty
    def isUp(self):
        pass

    @abstractproperty
    def name(self):
        pass

    #methods
    @abstractmethod
    def createTunTapAdapter(self, ipAddress, macAddress):
        pass

    @abstractmethod
    def openTunTap(self):
        pass

    @abstractmethod
    def closeTunTap(self):
        pass

    @abstractmethod
    def startRead(self, sender, senderArgs):
        pass

    @abstractmethod
    def startWrite(self, writeQ):
        pass

    @abstractmethod
    def stopRead(self):
        pass

    @abstractmethod
    def stopWrite(self):
        pass

    # protected methods
    @abstractmethod
    def _getMac(self):
        pass

    @abstractmethod
    def _getIP(self):
        pass


class abstractThreading(threading.Thread):
    __metaclass__ = ABCMeta
    def __init__(self, *args, **kwargs):
        super(abstractThreading, self).__init__()


class SniffBase(abstractThreading):
    def __init__(self):
        super(SniffBase, self).__init__()

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def process(self):
        pass

    @abstractmethod
    def send(self):
        pass


class WriteBase(abstractThreading):
    def __init__(self):
        super(WriteBase, self).__init__()

    @abstractmethod
    def run(self):
        pass