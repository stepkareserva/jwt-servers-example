package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"crypto/rand"
	"encoding/hex"

	"github.com/dgrijalva/jwt-go"
)

/*
master node with jwt authorization:

/new-node?username="node-user":
	master creates config for node:
		1. secret key used in node
		2. token for node to access master
		3. token for master to access node
	1. and 2. return passed as responce to /new-node",
	3 stored in `nodeAccessToken` variable

/protected
	check client's jwt token and responce hello if correct

/test-node
	access to node/protected with jwt token

*/

var (
	secret          = []byte("master_secret_key")
	nodeAccessToken string
)

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type NewNodeRequest struct {
	Username string `json:"username"`
}

type NewNodeResponse struct {
	Secret            []byte `json:"secret"`
	MasterAccessToken string `json:"master_access_token"`
}

func main() {
	http.HandleFunc("/new-node", newNodeHandler)
	http.HandleFunc("/protected", protectedHandler)
	http.HandleFunc("/test-node", testNodeHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func newNodeHandler(w http.ResponseWriter, r *http.Request) {
	// extract node user name from payload
	var node NewNodeRequest
	err := json.NewDecoder(r.Body).Decode(&node)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// generate jwt to access master
	masterAccessToken, err := generateToken(secret, node.Username)
	if err != nil {
		http.Error(w, "Error creating master access token", http.StatusInternalServerError)
		return
	}

	// generate secret for new node
	nodeSecret, err := generateSecretKey()
	if err != nil {
		http.Error(w, "Failed to generate node secret", http.StatusInternalServerError)
		return
	}

	// genetate jwt to access new node from master
	nodeAccessToken, err = generateToken(nodeSecret, "master")
	if err != nil {
		http.Error(w, "Error creating node access token", http.StatusInternalServerError)
		return
	}

	response := NewNodeResponse{
		Secret:            nodeSecret,
		MasterAccessToken: masterAccessToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func generateSecretKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(key)), nil
}

func generateToken(secret []byte, username string) (string, error) {
	tokenExpirationTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: tokenExpirationTime.Unix(),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	if !token.Valid {
		http.Error(w, "Unaithorized token", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Welcome to master protected endoint, %s!", claims.Username)))
}

func testNodeHandler(w http.ResponseWriter, r *http.Request) {
	// send the request to the node/protected with jwt
	req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	req.Header.Add("Authorization", nodeAccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// read the response from the node
	nodeResponce, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusInternalServerError)
		return
	}

	// Forward the response to the client
	body := fmt.Sprintf("Node /protected responce: %s\n", string(nodeResponce))
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(body))
}
