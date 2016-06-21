from flask import Flask, request
from flask_api import status
import Queue
import json

from AtumsoftBase import VIRTUAL_ADAPTER_TUPLE


app = Flask(__name__)
app.config.from_object(__name__)
app.debug = False
inputQ = Queue.Queue()

@app.route('/getinfo',methods=['GET'])
def getinfo(*args, **kwargs):
    return json.dumps(str(VIRTUAL_ADAPTER_TUPLE))

@app.route('/', defaults={'path': ''},methods=['POST'])
@app.route('/<path:path>',methods=['POST'])
def main(path, *args, **kwargs):
    inputQ.put(request.data)
    return request.data, status.HTTP_200_OK

def run():
    app.run(host='0.0.0.0')

