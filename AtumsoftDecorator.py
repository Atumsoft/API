import AtumsoftBase
import AtumsoftUtils
import abc
import sys
import os
import ctypes


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

    @property
    def gateway(self):
        return self.tunTap.gateway

    @property
    def activeHosts(self):
        return self.tunTap.activeHosts

    def __init__(self, isVirtual=True):

        # need to be run as admin, if not quit
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        if not is_admin:
            raise AtumsoftBase.NotAuthorizedException('Must be run as an admin!')

        # get all supported platforms
        self.supportedPlatforms = [cls for cls in AtumsoftBase.TunTapBase.__subclasses__() if cls is not AtumsoftDecorator]
        self.platform = sys.platform

        # find first class that supports platform
        for cls in self.supportedPlatforms:
            if str(cls.platform).upper() in str(self.platform).upper():
                self.tunTap = cls(isVirtual)
                break

        if not 'tunTap' in self.__dict__:
            print "platform not supported yet"
            raise NotImplementedError

    def getPlatform(self):
        return self.platform

    def createTunTapAdapter(self,name, ipAddress='', macAddress=''):
        return self.tunTap.createTunTapAdapter(name,ipAddress, macAddress)

    def openTunTap(self):
        return self.tunTap.openTunTap()

    def closeTunTap(self):
        return self.tunTap.closeTunTap()

    def startCapture(self, *args, **kwargs):
        return self.tunTap.startCapture(*args, **kwargs)

    def stopCapture(self):
        return self.tunTap.stopCapture()

    def listen(self):
        return self.tunTap.listen()

    # protected methods

    def _startRead(self, sender=AtumsoftUtils.POST, senderArgs=('0.0.0.0',)):
        return self.tunTap.startRead(sender, senderArgs)

    def _startWrite(self, writeQ):
        return self.tunTap.startWrite()

    def _stopRead(self):
        return self.tunTap.stopRead()

    def _stopWrite(self):
        return self.tunTap.stopWrite()

    def _findHosts(self):
        return self.tunTap._findHosts()

    def _getMac(self):
        return self.tunTap._getMac()

    def _findGateway(self):
        return self.tunTap._findGateway()
