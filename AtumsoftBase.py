from abc import ABCMeta, abstractmethod


class TunTapBase(metaclass=ABCMeta):
    @abstractmethod
    def createTunTapAdapter(self):
        pass

    @abstractmethod
    def openTunTap(self):
        pass

    @abstractmethod
    def closeTunTap(self):
        pass


class SniffBase(metaclass=ABCMeta):
    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def process(self):
        pass

    @abstractmethod
    def send(self):
        pass


class WriteBase(metaclass=ABCMeta):
    @abstractmethod
    def run(self):
        pass