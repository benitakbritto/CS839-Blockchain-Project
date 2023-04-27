# Usage: python run.py -f upload -s 5001 -d testfile.txt
# Usage: python run.py -f share -s 5001 -r 5002 -t <>

import server
import requests
import keygenreader as kgr
import json

# Globals
base_url = "http://localhost:"

def call_upload(sender_port, data_to_upload):
    key_dict_sender = kgr.KeyFileReader(f'{str(sender_port)}.json').get_keys()
    
    data = {}
    data["sender_pk"] = key_dict_sender["public_key_addr"]
    data["file"] = data_to_upload
    
    r = requests.post(f"{base_url}{str(sender_port)}/upload", json=data)
    assert r.status_code == 201

def call_share(sender_port, receiver_port, txn_ref):
    key_dict_sender = kgr.KeyFileReader(f'{str(sender_port)}.json').get_keys()
    key_dict_receiver = kgr.KeyFileReader(f'{str(receiver_port)}.json').get_keys()
    
    data = {}
    data["sender_pk"] = key_dict_sender["public_key_addr"]
    data["receiver_pk"] = key_dict_receiver["public_key_addr"]
    data["receiver_r_pk"] = key_dict_receiver["reencrypt_public_key"]
    data["data_txn_ref"] = txn_ref
    
    r = requests.post(f"{base_url}{str(sender_port)}/share", json=data)
    assert r.status_code == 201

if __name__ == "__main__":
    # CLI
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument(
        "-f", "--function", type=str, help="upload/share"
    )
    parser.add_argument(
        "-s", "--senderport", type=int, help="Sender port"
    )
    parser.add_argument(
        "-r", "--receiverport", type=int, help="Receiver port"
    )
    parser.add_argument(
        "-d", "--data", type=str, help="Data to upload"
    )
    parser.add_argument(
        "-t", "--txnref", type=str, help="Transaction reference"
    )
    
    args = parser.parse_args()
    
    # Run
    if args.function == "upload":
        call_upload(args.senderport, args.data) 
    elif args.function == "share":
        call_share(args.senderport, args.receiverport, args.txnref)