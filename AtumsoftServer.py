from flask import Flask, request
# from flask_api import status
import Queue
import json

from AtumsoftBase import VIRTUAL_ADAPTER_DICT


app = Flask(__name__)
app.config.from_object(__name__)
app.debug = False
inputQ = Queue.Queue()

@app.route('/getinfo',methods=['GET'])
def getinfo(*args, **kwargs):
    print VIRTUAL_ADAPTER_DICT
    return json.dumps(str(VIRTUAL_ADAPTER_DICT))

@app.route('/addRoute',methods=['POST'])
def addroute(*args, **kwargs):
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

