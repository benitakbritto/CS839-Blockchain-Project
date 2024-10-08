# Yelling Secrets into a Crowd: Private Document Sharing on a Public Blockchain

### Brief
Private-file-sharing code on top of the [p2b-blockchain code](https://gist.github.com/darkryder/5a92647cd268458239720eec44a5d8a7).

### File Structure
workspace  
|__pyring  
|__CS839-Blockchain-Project (this repo)  
|____src // contains our source code  
|_______data // contains test data we used to run our code  
|____Deliverables // contains documents we submitted as part of our course project  


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
3. `curl http://localhost:5001/startexp/`
4. To invoke the APIs, use: 
    - `python3 src/run.py -f startexp -s 5001` to start
    - `python3 src/run.py -f upload -s 5001 -d <file to share>` to upload  
    - `python3 src/run.py -f share -s 5001 -r 5002 -t <txn ref of upload>` to share

### Demo
Link to our demo can be found [here](https://drive.google.com/file/d/1iiJntQNEOz9gPwWnbHgYZVDrS7mmgfvX/view?usp=sharing)
