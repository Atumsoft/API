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


class SniffBase(object, threading.Thread):
    __metaclass__ = ABCMeta

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def process(self):
        pass

    @abstractmethod
    def send(self):
        pass


class WriteBase(object, threading.Thread):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(WriteBase, self).__init__()

    @abstractmethod
    def run(self):
        pass