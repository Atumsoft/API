from subprocess import Popen,PIPE,STDOUT
import threading

# This only works on linux with netdiscover installed.

class ArpScanner():

    def __init__(self):
        self.shouldThreadRun = True
        self.interface = ""
        self.runThread = None
        self.runThread = threading.Thread(target=self.run)
        self.runThread.setDaemon(True)

    def startup(self, interface="wlp2s0"):
        self.interface = interface
        self.runThread.start()

    def shutdown(self):
        self.shouldThreadRun = False

    def run(self):
        process = Popen('netdiscover -S -P -i '+self.interface, stdout=PIPE, stderr=STDOUT, shell=True)
        while self.shouldThreadRun:
            line = process.stdout.readline()
            if not line: break
            if line.startswith(" _") or line.startswith(" -") or line.startswith("  "):
                pass
            else:
                print line.split()
