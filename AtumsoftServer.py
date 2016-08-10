import ast
import socket
import sys

import time

import Queue
import json
import thread
import os

from tornado import tcpserver
from tornado import web
from tornado import ioloop
from MethodDispatcher import MethodDispatcher


class SocketServer(tcpserver.TCPServer):
    def handle_stream(self, stream, address):
        stream.read_until_close(streaming_callback=self.printData)

    def printData(self, data):
        print data

class ConnectHandler(MethodDispatcher):
    def index(self):
        if not self.request.body: return
        newPort = int(self.request.body)
        server.listen(newPort)

    def connect(self):
        ioloop.IOLoop.current().add_callback_from_signal(_connect_to_host, ast.literal_eval(self.request.body))

    def getinfo(self):
        print repr(self.request)
        self.write(json.dumps(virtualAdapterInfoDict))

    def disconnect(self):
        pass


def _connect_to_host(host=None): # there is probably a better way to handle the connection event
    eventQueue.put(host)

def runConnectionServer(hostQueue, infoDict):
    global eventQueue
    eventQueue = hostQueue

    global virtualAdapterInfoDict
    virtualAdapterInfoDict = infoDict

    app = web.Application([
        (r'/.*', ConnectHandler)
    ])
    app.listen(5000)

    ioloop.IOLoop.current().start()

def runSocketServer():
    global server
    server = SocketServer()
    server.listen(8000)
    # app = web.Application([
    #     (r"/", SocketServer),
    # ])
    # app.listen(6000)
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

# NumberOfServers = 0
#
#
#
# app = Flask(__name__)
# app.config.from_object(__name__)
# app.debug = False
inputQ = Queue.Queue()
outputQ = Queue.Queue()
hostInfoDict = {}
#
# @app.route('/getinfo',methods=['GET'])
# def getinfo(*args, **kwargs):
#     print VIRTUAL_ADAPTER_DICT
#     return json.dumps(str(VIRTUAL_ADAPTER_DICT))
#
# @app.route('/connect',methods=['GET', 'POST'])
# def verify(*args, **kwargs):
#     print 'data: %s' % request.data
#     host = request.remote_addr
#     print 'host: %s' % host
#
#     hostInfoDict[host] = {'address' : ast.literal_eval(request.data)}
#     try:
#         data = ast.literal_eval(request.data)
#         print data
#         sock = Atumsock(data.pop('port'))
#         sock.socketRun(host)
#     except Exception, e:
#         print e.message
#         pass
#     print'ran'
#     return request.data, 200
#
# @app.route('/disconnect', methods=['POST'])
# def disconnect(*args, **kwargs):
#     pass
#
# def shutdown_server():
#     func = request.environ.get('werkzeug.server.shutdown')
#     if func is None:
#         raise RuntimeError('Not running with the Werkzeug Server')
#     func()
#
# @app.route('/shutdown')
# def stop(*args, **kwargs):
#     shutdown_server()
#
# # @app.route('/', defaults={'path': ''},methods=['POST'])
# # @app.route('/<path:path>',methods=['POST'])
# # def main(path, *args, **kwargs):
# #     inputQ.put(request.data)
# #     return request.data, 200
#
# def runServer():
#     print NumberOfServers
#     app.run(host='0.0.0.0', port=5000+NumberOfServers)
#
# # Socket Code ==========================================================================================================
# class Atumsock:
#     listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sendSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
#     def __init__(self, port):
#         try:
#             self.listenSock.bind((getIP(), port))
#         except socket.error:
#             print 'already connected'
#
#         self.port = port
#
#     def socketRun(self, connectAddr=''):
#         thread.start_new_thread(self.send, (connectAddr,))
#         thread.start_new_thread(self.listen, tuple())
#         print 'socket threads starting'
#
#     def send(self, connectAddr=''):
#         while 1:
#             try:
#                 self.sendSock.connect((connectAddr, self.port))
#                 print 'connected!'
#                 break
#             except:
#                 time.sleep(2)
#                 print 'can\'t connect to host at %s' % connectAddr
#         while 1:
#             if not outputQ: continue
#             data = outputQ.get()
#             self.sendSock.send('start%send\n' % str(data))
#
#     def listen(self):
#         while 1:
#             self.listenSock.listen(2)
#             conn, addr = self.listenSock.accept()
#             incompleteData = ''
#
#             while 1:
#                 data = conn.recv(4096)
#                 if data:
#                     for packets in data.split('\n'):
#                         if not packets.strip(): continue
#
#                         if incompleteData:
#                             packets = incompleteData+packets
#                             incompleteData = ''
#
#                         if packets.startswith('start'):
#                             if packets.endswith('end'):
#                                 packets = packets.replace('start','').replace('end','')
#                                 inputQ.put(packets)
#                             else:
#                                 incompleteData = packets
#                 else:
#                     break
