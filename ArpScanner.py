from subprocess import Popen,PIPE,STDOUT
import threading
from distutils.spawn import find_executable
import select

# This only works on linux with netdiscover installed.

class ArpScanner():

    def __init__(self):
        if find_executable("netdiscover") == None:
            raise Exception("netdiscover is not installed. Cannot be used")
        self.shouldThreadRun = True
        self.interface = ""
        self.callback = None #Callback must accept one param for data or the boogyman will get you.
        self.runThread = None
        self.runThread = threading.Thread(target=self.run)
        self.runThread.setDaemon(True)

    def startupBlockingGetFirstLine(self, interface="eth0"):
        self.interface = interface
        stop = False
        output = ""
        process = Popen('netdiscover -S -P -i ' + self.interface, bufsize=1, stdout=PIPE, stderr=STDOUT, shell=True)
        pollObj = select.poll()
        pollObj.register(process.stdout, select.POLLIN)
        while not stop:
            pollResult = pollObj.poll(0)
            if pollResult:
                line = process.stdout.readline()
                if not line: break
                if line.startswith(" _") or line.startswith(" -") or line.startswith("  "):
                    pass
                else:
                    output = line.split()
                    stop = True
                if process.returncode is not None:
                    stop = True
        if process.returncode is None:
            process.kill()
        return output

    def startup(self, interface="eth0"):
        self.interface = interface
        self.runThread.start()

    def shutdown(self):
        self.shouldThreadRun = False

    def registerCallback(self, callback):
        self.callback = callback

    def unregisterCallback(self):
        self.callback = None

    def run(self):
        process = Popen('netdiscover -S -P -i '+self.interface, stdout=PIPE, stderr=STDOUT, shell=True)
        while self.shouldThreadRun:
            line = process.stdout.readline()
            if not line: break
            if line.startswith(" _") or line.startswith(" -") or line.startswith("  "):
                pass
            else:
                self.callback(line.split())
            if process.returncode is not None:
                self.shouldThreadRun = False
        if process.returncode is None:
            process.kill()

    #Example method that could be used as a callback.
    #def testCallback(self, data):
    #    print data
