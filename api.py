#!flask/bin/python
import json
import pika
from flask import Flask, abort, jsonify, request, make_response

app = Flask(__name__)

@app.route('/posthostinfo', methods=['POST'])
def host_info():
    if not request.json or not 'ipaddress' in request.json:
        abort(400)
    req = request.get_json()
    print(req) 
    hostname = req['hostname']
    ipaddress = req['ipaddress']
    mac = req['MAC']
    connection = pika.BlockingConnection(pika.ConnectionParameters('192.168.40.150'))
    channel = connection.channel()
    channel.queue_declare(queue='hostinfo')

    channel.basic_publish(exchange='',
                        routing_key='hostinfo',
                        body=json.dumps(req))

    print("[+] sent message" ) 

   # print(hostname)
   # print(ipaddress)
   # print(mac)
    return ' ', 204


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True, use_reloader=False)
    print("this works too")
