curl http://localhost:5001/startexp/
sleep 1

# Exchange public keys
curl -X POST http://localhost:5001/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5001", "recipient": "5002", "amount": 6000}'
sleep 5
curl -X POST http://localhost:5002/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5002", "recipient": "5003", "amount": 3000}'
sleep 5
curl -X POST http://localhost:5003/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5003", "recipient": "5001", "amount": 1}'
sleep 5

# Send symmetric key
curl -X POST http://localhost:5001/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5001", "recipient": "5002", "amount": 1}'
sleep 5
curl -X POST http://localhost:5002/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5002", "recipient": "5003", "amount": 1}'
sleep 5
curl -X POST http://localhost:5003/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5003", "recipient": "5001", "amount": 1}'
sleep 5

# Send file from 5001 to 5002
curl -X POST http://localhost:5001/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5001", "recipient": "5002", "amount": 1, "data": "test2b.py"}'
sleep 5
# Send file from 5002 to 5003
curl -X POST http://localhost:5002/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5002", "recipient": "5003", "amount": 1, "data": "p2b.md"}'
sleep 5
# Send file from 5003 to 5001
curl -X POST http://localhost:5003/transactions/new -H 'Content-Type: application/json' -d '{"sender": "5003", "recipient": "5001", "amount": 1, "data": "server.py"}'
sleep 5

