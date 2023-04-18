# CS839-Blockchain-Project

### Brief
Private-file-sharing code on top of the p2b-blockchain code.

### Setup
1. `python -m venv env` [One time only]
2. `source env/bin/activate` 
3. `chmod 777 setup.sh`
4. `./setup.sh` to install required packages

### Run
0. Generate reencryption keys for the blockchain nodes `python src/keygen.py -f <output-file-name>`
1. Run blockchain nodes `python server.py python3 src/server.py -p 5001 -n 5001 5002 5003 -f <key-gen-file-name>`
