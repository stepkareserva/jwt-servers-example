package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt"
)

/*
node with jwt authorization:

main.go -config node_config.json
	initialize config with given secret and master access key

/protected
	check client's jwt token and responce hello if correct

/test-master
	access to master/protected with jwt token

*/

type NodeConfig struct {
	Secret            []byte `json:"secret"`
	MasterAccessToken string `json:"master_access_token"`
}

var config *NodeConfig

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	// parsing config, initialization
	var configFile string
	flag.StringVar(&configFile, "config", "config.json", "Path to the configuration file")
	flag.Parse()

	// Загрузка конфигурации
	var err error
	config, err = loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
		return
	}

	// handlers
	http.HandleFunc("/protected", protectedHandler)
	http.HandleFunc("/test-master", testMasterHandler)

	// start the client server on port 8081
	log.Println("Client server started on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func loadConfig(filePath string) (*NodeConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %v", err)
	}

	return config, nil
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return config.Secret, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}
		log.Println(err)
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	if !token.Valid {
		http.Error(w, "Unauthorized token", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Welcome to node protected endpoint, %s!", claims.Username)))
}

func testMasterHandler(w http.ResponseWriter, r *http.Request) {
	// send the request to the master/protected with jwt
	req, err := http.NewRequest("GET", "http://localhost:8080/protected", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	req.Header.Add("Authorization", config.MasterAccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// read the response from the master
	masterResponce, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusInternalServerError)
		return
	}

	// Forward the response to the client
	body := fmt.Sprintf("Master /protected responce: %s\n", string(masterResponce))
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(body))
}
