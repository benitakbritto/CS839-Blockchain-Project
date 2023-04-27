# CS839-Blockchain-Project

### Brief
Private-file-sharing code on top of the p2b-blockchain code.

### File Structure
workspace  
|__pyring  
|__CS839-Blockchain-Project  
|____src  

### Setup
1. `mkdir workspace`
2. `cd workspace`
3. `python -m venv env`
4. `python -m venv env` 
5. Setup pyring: 
    - `git clone --recurse-submodules https://github.com/bartvm/pyring.git`
    - `cd pyring`
    - `python setup.py build`
    - `python setup.py develop`
6. Setup this repository:
    - `git clone ...`
    - `cd <repo>`
    - `chmod 777 setup.sh`
    - `./setup.sh` to install required packages


### Run
0. Generate reencryption keys for the blockchain nodes `python3 src/keygen.py -f <output-file-name>`
1. Run the proxy, `python3 proxy-reencryption.py -p <port num>`. Right now it is hardcoded to port 5000. 
2. Run blockchain nodes `python3 src/server.py -p 5001 -n 5001 5002 5003 -f <key-gen-file-name>`
3. Run sample APIs given in `src/test-cmd-server.txt`.
