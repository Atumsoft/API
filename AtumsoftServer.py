from flask import Flask, request
from flask.ext.api import status
import Queue


app = Flask(__name__)
app.config.from_object(__name__)
app.debug = False
inputQ = Queue.Queue()


@app.route('/', defaults={'path': ''},methods=['POST'])
@app.route('/<path:path>',methods=['POST'])
def main(path, *args, **kwargs):
    inputQ.put(request.data)
    return request.data, status.HTTP_200_OK

def run():
    app.run(host='0.0.0.0')

