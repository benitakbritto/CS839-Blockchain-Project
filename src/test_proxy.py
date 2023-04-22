import proxy_encryption_server
import json
import requests
import umbral


def pack_json(
    sender_pk, receive_pk, capsule, kfrag
) -> dict[str, str]:
    data = {}
    data["sender_pk"] = bytes(sender_pk).hex()
    data["receiver_pk"] =bytes(receive_pk).hex()
    data["capsule"] = bytes(capsule).hex()
    data["kfrag_hex"] = bytes(kfrag).hex()

    return data

def get_test_input():
  sender_private_key = umbral.SecretKey.random()
  sender_public_key = sender_private_key.public_key()
  plaintext = b'hello world'
  capsule, _ = umbral.encrypt(sender_public_key, plaintext)
  
  sender_signing_key = umbral.SecretKey.random()
  sender_signer = umbral.Signer(sender_signing_key)
  
  receiver_private_key = umbral.SecretKey.random()
  receiver_public_key = receiver_private_key.public_key()
  
  M, N = 1, 1 
  kfrags = umbral.generate_kfrags(delegating_sk=sender_private_key,
                          receiving_pk=receiver_public_key,
                          signer=sender_signer,
                          threshold=M,
                          shares=N)
  
  return sender_public_key, receiver_public_key, capsule, kfrags

def test_simple():
    sender_public_key, receiver_public_key, capsule, kfrags = get_test_input()
    
    data = pack_json(sender_public_key, receiver_public_key, capsule, kfrags[0])
    r = requests.post(f"{proxy_base_url}post/kfrag", json=json.dumps(data))
    assert r.status_code == 201

    r = requests.get(f"{proxy_base_url}get/kfrag/{bytes(sender_public_key).hex()}/{bytes(receiver_public_key).hex()}/{bytes(capsule).hex()}")
    assert r.status_code == 200

    print(f"Passed test_simple!")

def test_get_without_put():
    sender_public_key, receiver_public_key, capsule, kfrags = get_test_input()

    data = pack_json(sender_public_key, receiver_public_key, capsule, kfrags[0])

    r = requests.get(f"{proxy_base_url}get/kfrag/{data['sender_pk']}/{data['receiver_pk']}/{data['capsule']}")
    assert r.status_code == 400

    print(f"Passed test_get_without_put!")

def test_missing_post_fields():
    sender_public_key, receiver_public_key, capsule, kfrags = get_test_input()

    data = pack_json(sender_public_key, receiver_public_key, capsule, kfrags[0])
    data.pop("capsule", None)
    r = requests.post(f"{proxy_base_url}post/kfrag", json=json.dumps(data))
    assert r.status_code == 400

    print(f"Passed test_missing_post_fields!")

def test_missing_get_fields():
    sender_public_key, receiver_public_key, capsule, kfrags = get_test_input()

    data = pack_json(sender_public_key, receiver_public_key, capsule, kfrags[0])
    r = requests.post(f"{proxy_base_url}post/kfrag", json=json.dumps(data))
    assert r.status_code == 201

    r = requests.get(f"{proxy_base_url}get/kfrag/{data['sender_pk']}/{data['receiver_pk']}")
    assert r.status_code == 404

    print(f"Passed test_missing_get_fields!")


if __name__ == "__main__":
    proxy_base_url = "http://localhost:5000/"

    test_simple()
    test_get_without_put()
    test_missing_post_fields()
    test_missing_get_fields()
