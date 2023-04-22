import proxy_encryption_server
import json
import requests

def pack_json(sender_pk: str, receive_pk: str, capsule: str, kfrag_hex: str) -> dict[str, str]:
  data = {}
  data['sender_pk'] = sender_pk
  data['receiver_pk'] = receive_pk
  data['capsule'] = capsule
  data['kfrag_hex'] = kfrag_hex
  
  return data

def test_simple():
  sender_pk = 'a'
  receiver_pk = 'b'
  capsule = 'c'
  kfrag_hex = 'd'
  
  data = pack_json(sender_pk, receiver_pk, capsule, kfrag_hex)
  r = requests.post(f'{proxy_base_url}post/kfrag', json=json.dumps(data))
  assert(r.status_code == 201)
  
  r = requests.get(f'{proxy_base_url}get/kfrag/{sender_pk}/{receiver_pk}/{capsule}')
  assert(r.status_code == 200)
  assert(json.loads(r.text)['kfrag_hex'] == kfrag_hex)
  
  print(f'Passed test_simple!') 
 
def test_get_without_put():
  sender_pk = 'e'
  receiver_pk = 'f'
  capsule = 'g'
  kfrag_hex = 'h'
  
  r = requests.get(f'{proxy_base_url}get/kfrag/{sender_pk}/{receiver_pk}/{capsule}')
  assert(r.status_code == 400)
  
  print(f'Passed test_get_without_put!') 

def test_missing_post_fields():
  sender_pk = 'a'
  receiver_pk = 'b'
  capsule = 'c'
  kfrag_hex = 'd'
  
  data = pack_json(sender_pk, receiver_pk, capsule, kfrag_hex)
  data.pop('capsule', None)
  r = requests.post(f'{proxy_base_url}post/kfrag', json=json.dumps(data))
  assert(r.status_code == 400)
  
  print(f'Passed test_missing_post_fields!') 

def test_missing_get_fields():
  sender_pk = 'a'
  receiver_pk = 'b'
  capsule = 'c'
  kfrag_hex = 'd'
  
  data = pack_json(sender_pk, receiver_pk, capsule, kfrag_hex)
  r = requests.post(f'{proxy_base_url}post/kfrag', json=json.dumps(data))
  assert(r.status_code == 201)
  
  r = requests.get(f'{proxy_base_url}get/kfrag/{sender_pk}/{capsule}')
  assert(r.status_code == 404)
  
  print(f'Passed test_missing_get_fields!') 


if __name__ == '__main__':
  proxy_base_url = 'http://localhost:5000/'

  test_simple()
  test_get_without_put()
  test_missing_post_fields()
  test_missing_get_fields()