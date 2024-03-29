from abc import ABCMeta, abstractmethod, abstractproperty
import threading
import Queue



class TunTapBase(object):
    """
    Superclass of all tuntap implementations. Aims to be agnostic for all possible platforms.
    """
    __metaclass__ = ABCMeta

    VIRTUAL_ADAPTER_DICT = {}  # dict containing ipaddress for the key and mac addr for the value

    # properties
    @abstractproperty
    def ipAddress(self):
        pass

    @abstractproperty
    def macAddress(self):
        pass

    @abstractproperty
    def isUp(self):
        pass

    @abstractproperty
    def name(self):
        pass

    @abstractproperty
    def gateway(self):
        pass

    @abstractproperty
    def activeHosts(self):
        pass

    #methods
    @abstractmethod
    def listen(self):
        pass

    @abstractmethod
    def createTunTapAdapter(self,name, ipAddress, macAddress):
        pass

    @abstractmethod
    def openTunTap(self):
        pass

    @abstractmethod
    def closeTunTap(self):
        pass

    @abstractmethod
    def startCapture(self):
        pass

    @abstractmethod
    def stopCapture(self):
        pass

    # protected methods

    @abstractmethod
    def _startRead(self, hostIP):
        pass

    @abstractmethod
    def _startWrite(self, writeQ):
        pass

    @abstractmethod
    def _stopRead(self):
        pass

    @abstractmethod
    def _stopWrite(self):
        pass

    @abstractmethod
    def _getMac(self):
        pass

# TunTapBase.register(AtumsoftWindows.AtumsoftWindows)

class abstractThreading(threading.Thread):
    __metaclass__ = ABCMeta
    def __init__(self, *args, **kwargs):
        super(abstractThreading, self).__init__()


class SniffBase(abstractThreading):
    def __init__(self):
        super(SniffBase, self).__init__()
        # self.postQ = Queue.Queue()

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def process(self,pkt):
        pass


class WriteBase(abstractThreading):
    def __init__(self):
        super(WriteBase, self).__init__()

    @abstractmethod
    def run(self):
        pass


# Errors

class PropertyNotDefinedException(Exception):
    pass

class NotAuthorizedException(Exception):
    pass
