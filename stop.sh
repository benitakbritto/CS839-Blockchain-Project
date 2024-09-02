start=$1
for((i=0; i<4; i++)); do
    PID=$(lsof -i tcp:$((start+i)) | awk 'NR>1 {print $2}')
    kill -9 $PID
done