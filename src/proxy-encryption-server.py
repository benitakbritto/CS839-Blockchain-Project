# Usage: python3 proxy-reencryption.py -p <port num>

from umbral import generate_kfrags
from flask import Flask, request, jsonify
import json
from argparse import ArgumentParser
import logging

app = Flask(__name__)

# In-mem state
class Proxy_State:
  def __init__(self):
    # stores key: node id, value: single kfrag in hex
    self.kfrag_dict = {}
  
  def update_kfrag(self, user, kfrag):
    self.kfrag_dict[user] = kfrag

  def get_kfrag(self, user):
    assert(user in self.kfrag.keys() == True)
    
    return self.kfrag_dict[user]



@app.route('/receive/kfrag', methods=['POST'])
def new_kfrag_received():
  values = json.loads(request.get_json())
  logging.info(values);  
  logging.info(type(values));  

  required = ['user', 'kfrag_hex']
  if not all(req in values for req in required):
    return 'Missing values', 400

  user = values['user']
  kfrag_hex = values['kfrag_hex']
  proxy_state.kfrag_dict[user] = kfrag_hex
  

  return "OK", 201

@app.route('/get/kfrag/<user>', methods=['GET'])
def get_kfrag(user):
  response = {
    'kfrag': proxy_state.kfrag_dict[user]
  }

  return jsonify(response), 200

if __name__ == '__main__':
  logging.getLogger().setLevel(logging.INFO)
  
  parser = ArgumentParser()
  parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
  
  args = parser.parse_args()
  port = args.port 
  
  proxy_state = Proxy_State() 
  app.run(host='0.0.0.0', port=port)
