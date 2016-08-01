import ast
import socket
import sys

import time
from flask import Flask, request
import Queue
import json
import thread
import os

from AtumsoftBase import VIRTUAL_ADAPTER_DICT
from AtumsoftUtils import getIP



app = Flask(__name__)
app.config.from_object(__name__)
app.debug = False
inputQ = Queue.Queue()
outputQ = Queue.Queue()
hostInfoDict = {}

@app.route('/getinfo',methods=['GET'])
def getinfo(*args, **kwargs):
    print VIRTUAL_ADAPTER_DICT
    return json.dumps(str(VIRTUAL_ADAPTER_DICT))

@app.route('/connect',methods=['GET', 'POST'])
def verify(*args, **kwargs):
    print 'data: %s' % request.data
    host = request.remote_addr
    print 'host: %s' % host

    hostInfoDict[host] = {'address' : ast.literal_eval(request.data)}

    socketRun()
    print'ran'
    return request.data, 200

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/shutdown')
def stop(*args, **kwargs):
    shutdown_server()

# @app.route('/', defaults={'path': ''},methods=['POST'])
# @app.route('/<path:path>',methods=['POST'])
# def main(path, *args, **kwargs):
#     inputQ.put(request.data)
#     return request.data, 200

def runServer():
    app.run(host='0.0.0.0')

# Socket Code ==========================================================================================================
listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sendSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listenSock.bind((getIP(), 6001))

def socketRun():
    thread.start_new_thread(send, tuple())
    thread.start_new_thread(listen, tuple())
    print 'socket threads starting'

def send():
    while 1:
        try:
            sendSock.connect(('192.168.50.115', 6001))
            print 'connected!'
            break
        except:
            time.sleep(2)
            print 'can\'t connect'
    while 1:
        if not outputQ: continue
        data = outputQ.get()
        # print data
        sendSock.send('start%send\n' % str(data))

def listen():
    while 1:
        listenSock.listen(1)
        conn, addr = listenSock.accept()
        incompleteData = ''

        while 1:
            data = conn.recv(4096)
            if data:
                for packets in data.split('\n'):
                    if not packets.strip(): continue

                    if incompleteData:
                        packets = incompleteData+packets

                    if packets.startswith('start'):
                        if packets.endswith('end'):
                            packets = packets.replace('start','').replace('end','')
                            inputQ.put(packets)
                        else:
                            incompleteData = packets
                    print packets
            else:
                break