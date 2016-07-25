import ast
import sys
from flask import Flask, request
import Queue
import json
import thread
import os

from AtumsoftBase import VIRTUAL_ADAPTER_DICT



app = Flask(__name__)
app.config.from_object(__name__)
app.debug = False
inputQ = Queue.Queue()
hostInfoDict = {}

@app.route('/getinfo',methods=['GET'])
def getinfo(*args, **kwargs):
    print VIRTUAL_ADAPTER_DICT
    return json.dumps(str(VIRTUAL_ADAPTER_DICT))

@app.route('/addRoute',methods=['POST'])
def addroute(*args, **kwargs):
    return request.data, 200

@app.route('/connect',methods=['GET', 'POST'])
def verify(*args, **kwargs):
    print 'data: %s' % request.data
    host = request.remote_addr
    print 'host: %s' % host

    hostInfoDict[host] = {'address' : ast.literal_eval(request.data)}
    return request.data, 200

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/shutdown')
def stop(*args, **kwargs):
    shutdown_server()

@app.route('/', defaults={'path': ''},methods=['POST'])
@app.route('/<path:path>',methods=['POST'])
def main(path, *args, **kwargs):
    inputQ.put(request.data)
    return request.data, 200

def run():
    app.run(host='0.0.0.0')

def createDevice():
    from AtumsoftGeneric import AtumsoftGeneric
    tunTap = AtumsoftGeneric(isVirtual=False, iface='enp0s25') # physical on ethernet port
    # tunTap.createTunTapAdapter(name='mytun', ipAddress='192.168.2.101') # virtual for testing
    # tunTap.createTunTapAdapter()
    # tunTap.openTunTap()
    tunTap.startCapture()


# Helper functions to check for admin privileges on run ================================================================
def checkForAdmin():
    try:
        is_admin = os.getuid() == 0
        if not is_admin:
            print "Script not started as root. Running sudo.."
            args = ['sudo', sys.executable] + sys.argv + [os.environ]
            # the next line replaces the currently-running process with the sudo
            os.execlpe('gksudo', *args)

    except AttributeError:
        print 'this part of the code must be run on a Unix system only'


if __name__ == '__main__':
    checkForAdmin()
    # thread.start_new_thread(run(), tuple()) # FIXME: sending tuple() is a hacky way to overcome start_new_threads requirement on sending args
    createDevice()

