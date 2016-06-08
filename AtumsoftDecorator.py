import AtumsoftBase
import abc
import os, sys


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
            if cls.platform in self.platform:
                self.tunTap = cls
                self.tunTap._name = name
                self.tunTap.isVirtual = isVirtual
                break

        if not self.tunTap:
            print "platform not supported yet"
            raise NotImplementedError

    def getPlatform(self):
        return self.platform

    def createTunTapAdapter(self, ipAddress, macAddress):
        self.tunTap.createTunTapAdapter(ipAddress, macAddress)

    def openTunTap(self):
        self.tunTap.openTunTap()

    def closeTunTap(self):
        self.tunTap.closeTunTap()

    def startRead(self, sender, senderArgs):
        self.tunTap.startRead(sender, senderArgs)

    def startWrite(self, writeQ):
        self.tunTap.startWrite()
