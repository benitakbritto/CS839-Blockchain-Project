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
    # key: concat(sender_pk, receiver_pk)
    # value: single kfrag in hex
    self.kfrag_dict = {}
  
  def form_key(self, sender_pk: str, receiver_pk: str, capsule: str) -> str:
    return sender_pk + '_' + receiver_pk + '_' + capsule

  def update_state(self, sender_pk: str, receiver_pk: str, kfrag_hex: str, capsule: str) -> str:
    _key = self.form_key(sender_pk, receiver_pk, capsule)
    self.kfrag_dict[_key] = kfrag_hex

  def get_state(self, sender_pk: str, receiver_pk: str, capsule: str) -> str:
    _key = self.form_key(sender_pk, receiver_pk, capsule)
    
    if _key not in self.kfrag_dict.keys():
      return None
    
    return self.kfrag_dict[_key]

@app.route('/post/kfrag', methods=['POST'])
def post_kfrag():
  # Extract info from payload
  values = json.loads(request.get_json())
  logging.info(values);  
  required = ['sender_pk', 'receiver_pk', 'kfrag_hex', 'capsule']
  if not all(req in values for req in required):
    return 'Missing values', 400

  # Update state
  sender_pk = values['sender_pk']
  receiver_pk = values['receiver_pk']
  kfrag_hex = values['kfrag_hex']
  capsule = values['capsule']
  proxy_state.update_state(sender_pk, receiver_pk, kfrag_hex, capsule)
  
  return "OK", 201

@app.route('/get/kfrag/<sender_pk>/<receiver_pk>/<capsule>', methods=['GET'])
def get_kfrag(sender_pk, receiver_pk, capsule):
  kfrag_hex = proxy_state.get_state(sender_pk, receiver_pk, capsule)
  
  if kfrag_hex is None:
    return 'Missing key', 400
  
  response = {
    'kfrag_hex': kfrag_hex
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
