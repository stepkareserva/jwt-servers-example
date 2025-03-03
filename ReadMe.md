# Example to demonstrate servers interaction with JWT auth

Two servers: master and node. Both have public api for everyone and protected api for each other.

Master generates config for new node, new node runs and may communicate with master's protected api:

```sh
# run master in first (A) terminal
$ cd jwt-master && go run main.go
2025/03/03 09:35:57 Server started on :8080

# get new node config from another (B) terminal
$ curl -X POST http://localhost:8080/new-node -H "Content-Type: application/json" -d '{"username":"node-user"}' > jwt-node/node-config.json

# run node in B terminam
$ cd jwt-node && go run main.go -config node-config.json
2025/03/03 09:49:45 Client server started on :8081

#   test in third (C) terminal
# test access node from master
$ curl http://localhost:8080/test-node
Node /protected responce: Welcome to node protected endpoint, master!
# test access master from node
$ curl http://localhost:8081/test-master
Master /protected responce: Welcome to master protected endoint, node-user!
```
