port=$1
filepath=$2
python3 src/run.py -f startexp -s $port

python3 src/run.py -f upload -s $port -d $filepath