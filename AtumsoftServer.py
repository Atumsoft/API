import Queue
import ast
import json
import requests
import socket
import threading
import thread
import time

from tornado import ioloop
from tornado import tcpserver
from tornado import web

from MethodDispatcher import MethodDispatcher

inputQ = Queue.Queue()
hostInfoDict = {}


class ConnectHandler(MethodDispatcher):
    usedPorts = []

    def openSocket(self):
        print 'opening socket at port %s' % self.request.body
        if not self.request.body: return
        newPort = int(self.request.body)
        if newPort in self.usedPorts:
            print 'port %s already in use' % newPort
            return
        self.usedPorts.append(newPort)
        # newSock = IOSocket(newPort)

    def connect(self):
        ioloop.IOLoop.current().add_callback_from_signal(_connect_to_host, ast.literal_eval(self.request.body))

    def getinfo(self):
        self.write(json.dumps(virtualAdapterInfoDict))

    def disconnect(self):
        pass

    def getPorts(self):
        self.write(json.dumps(self.usedPorts))

# Socket Code ==========================================================================================================
class IOSocket(object):
    def __init__(self, remoteIP, port, selfIP=''):
        self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print 'connecting socket at %s:%s' % (selfIP, port)
        self.listenSock.bind((selfIP, port))

        self.port = port
        self.remoteIP = remoteIP

    def startSend(self, outputQ):
        thread.start_new_thread(self.send, (outputQ,))

    def startListen(self, inputQ):
        thread.start_new_thread(self.listen, (inputQ,))

    def send(self, outputQ):
        while 1:
            try:
                self.sendSock.connect((self.remoteIP, self.port))
                print 'connected!'
                break
            except Exception, e:
                time.sleep(2)
                print e.message
                print 'can\'t connect to host at %s:%s' % (self.remoteIP, self.port)
        while 1:
            if not outputQ: continue
            data = outputQ.get()
            self.sendSock.send('start%send\n' % str(data))

    def listen(self, inputQ):
        while 1:
            self.listenSock.listen(2)
            conn, addr = self.listenSock.accept()
            incompleteData = ''

            while 1:
                data = conn.recv(4096)
                if data:
                    for packets in data.split('\n'):
                        if not packets.strip(): continue

                        if incompleteData:
                            packets = incompleteData+packets
                            incompleteData = ''

                        if packets.startswith('start'):
                            if packets.endswith('end'):
                                packets = packets.replace('start','').replace('end','')
                                inputQ.put(packets)
                            else:
                                incompleteData = packets
                else:
                    continue


def _connect_to_host(host=None): # there is probably a better way to handle the connection event
    eventQueue.put(host)

def runConnectionServer(hostQueue=None, infoDict=None, runSocketServeronStart=False):
    global eventQueue
    eventQueue = hostQueue

    global virtualAdapterInfoDict
    virtualAdapterInfoDict = infoDict

    app = web.Application([
        (r'/.*', ConnectHandler)
    ])
    app.listen(5000)

    # if runSocketServeronStart:
    #     runSocketServer()

    ioloop.IOLoop.current().start()


def shutdown_server():
    print('Stopping http server')
    # ConnectHandler.server.stop()

    print('Will shutdown in %s seconds ...' % 3)
    io_loop = ioloop.IOLoop.instance()

    deadline = time.time() + 3

    def stop_loop():
        now = time.time()
        if now < deadline and (io_loop._callbacks or io_loop._timeouts):
            io_loop.add_timeout(now + 1, stop_loop)
        else:
            io_loop.stop()
            print('Shutdown')
    stop_loop()
