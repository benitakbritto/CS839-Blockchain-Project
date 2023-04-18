# Usage: python3 <python filename> -f <output file name>
from umbral import SecretKey, Signer
import json

# Generates the required keys and returns as json
def generate_keys():
  data = {}
  reencrypt_private_key = SecretKey.random()
  reencrypt_public_key = reencrypt_private_key.public_key()
  reencrypt_signing_key = SecretKey.random()
  reencrypt_verifying_key = reencrypt_signing_key.public_key()

  data['reencrypt_private_key'] = reencrypt_private_key.to_secret_bytes().hex()
  data['reencrypt_public_key'] = bytes(reencrypt_public_key).hex()
  data['reencrypt_signing_key'] = reencrypt_signing_key.to_secret_bytes().hex()
  data['reencrypt_verifying_key'] = bytes(reencrypt_verifying_key).hex()
  return json.dumps(data)
 
def write_to_file(path, json_str):
  with open(path, "w") as outfile:
    outfile.write(json_str)
    
if __name__ == '__main__':
  from argparse import ArgumentParser
  
  parser = ArgumentParser()
  parser.add_argument('-f', '--filename', type=str, help='file name to store generated keys', required=True)

  args = parser.parse_args()
  
  keys_str = generate_keys()
  write_to_file(args.filename, keys_str)  
