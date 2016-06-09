import AtumsoftBase
import AtumsoftUtils
import abc
import sys


class AtumsoftDecorator(AtumsoftBase.TunTapBase):
    __metaclass__ = abc.ABCMeta

    @property
    def ipAddress(self):
        return self.tunTap.ipAddress

    @property
    def macAddress(self):
        return self.tunTap.macAddress
    @property
    def isUp(self):
        return self.tunTap.isUp

    @property
    def name(self):
        return self.tunTap.name

    def __init__(self, name='', isVirtual=True):
        # get all supported platforms
        self.supportedPlatforms = [cls for cls in AtumsoftBase.TunTapBase.__subclasses__() if cls is not AtumsoftDecorator]
        self.platform = sys.platform

        # find first class that supports platform
        for cls in self.supportedPlatforms:
            if str(cls.platform).upper() in str(self.platform).upper():
                self.tunTap = cls(name, isVirtual)
                break

        if not 'tunTap' in self.__dict__:
            print "platform not supported yet"
            raise NotImplementedError

    def getPlatform(self):
        return self.platform

    def createTunTapAdapter(self, ipAddress='0.0.0.0', macAddress='\x4e\xe4\xd0\x38\xa1\xc5'):
        self.tunTap.createTunTapAdapter(ipAddress, macAddress)

    def openTunTap(self):
        self.tunTap.openTunTap()

    def closeTunTap(self):
        self.tunTap.closeTunTap()

    def startRead(self, sender=AtumsoftUtils.POST, senderArgs=('0.0.0.0',)):
        self.tunTap.startRead(sender, senderArgs)

    def startWrite(self, writeQ):
        self.tunTap.startWrite()

    def stopRead(self):
        self.tunTap.stopRead()

    def stopWrite(self):
        self.tunTap.stopWrite()

    def _getIP(self):
        self.tunTap._getIP()

    def _getMac(self):
        self.tunTap._getMac()
