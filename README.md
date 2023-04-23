# CS839-Blockchain-Project

### Brief
Private-file-sharing code on top of the p2b-blockchain code.

### Setup
1. `python -m venv env` [One time only]
2. `source env/bin/activate` 
3. `chmod 777 setup.sh`
4. `./setup.sh` to install required packages
5. Setup pyring: 
    - git clone --recurse-submodules https://github.com/bartvm/pyring.git
    - python setup.py build
    - python setup.py develop

### Run
0. Generate reencryption keys for the blockchain nodes `python src/keygen.py -f <output-file-name>`
1. Run the proxy, `python3 proxy-reencryption.py -p <port num>`. Right now it is hardcoded to port 5000. 
2. Run blockchain nodes `python3 src/server.py -p 5001 -n 5001 5002 5003 -f <key-gen-file-name>`
3. Run sample APIs given in `src/test-cmd-server.txt`.
