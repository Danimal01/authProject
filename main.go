package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
    "math/rand"
	"strconv"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"github.com/ethereum/go-ethereum/crypto"
	"encoding/hex"
	"io"
    "bytes"
	"strings"
	


)

var secretKey = "your_secret_key" // Change this to your own secret key

type User struct {
	gorm.Model
	Email    string `json:"email"`
	Password string `json:"password"`
	EthereumAddress string `json:"ethereum_address"` 

}

type Challenge struct {
    gorm.Model
    EthereumAddress string `json:"ethereum_address"`
    Nonce           int    `json:"nonce"`
}


// DB connection
var db *gorm.DB

func main() {
	// DB initialization
	var err error
	dsn := "user=postgres password=Danial dbname=cool sslmode=disable" // Replace with your DB credentials
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
		panic("Failed to connect to the database!")
	} else {
		fmt.Println("Connected to the database successfully")
	}

	db.AutoMigrate(&User{}, &Challenge{})

	r := mux.NewRouter()

	// User routes
	r.HandleFunc("/api/register", RegisterUser).Methods("POST")
	r.HandleFunc("/api/login", LoginUser).Methods("POST")

	//metamask routes
	r.HandleFunc("/api/connect-metamask", ConnectMetaMask).Methods("POST")
	r.HandleFunc("/api/challenge", CreateChallenge).Methods("POST")
    r.HandleFunc("/api/login-metamask", LoginWithMetamask).Methods("POST") 



	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:4200"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"*"},
	})

	handler := c.Handler(r)
	addr := ":8080"
	fmt.Printf("Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

// RegisterUser creates a new user
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user.Password = string(hash)
	db.Create(&user)

	json.NewEncoder(w).Encode(user)
}

// LoginUser logs in a user and returns a JWT
func LoginUser(w http.ResponseWriter, r *http.Request) {
	var user, userDB User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.Where("email = ?", user.Email).First(&userDB)

	err = bcrypt.CompareHashAndPassword([]byte(userDB.Password), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &jwt.StandardClaims{
		Subject:   userDB.Email,
		ExpiresAt: expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		http.Error(w, "Failed to create a token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "email": userDB.Email})
}


// ConnectMetaMask connects a MetaMask account
func ConnectMetaMask(w http.ResponseWriter, r *http.Request) {
	var user, userDB User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.Where("email = ?", user.Email).First(&userDB)

	userDB.EthereumAddress = user.EthereumAddress

	db.Save(&userDB)

	json.NewEncoder(w).Encode(userDB)
}

// Map of sessions to challenges. Replace with your session store.
var challenges = make(map[string]string)

// POST /api/challenge
func CreateChallenge(w http.ResponseWriter, r *http.Request) {
    var buf bytes.Buffer
    tee := io.TeeReader(r.Body, &buf)

    var challenge Challenge
    err := json.NewDecoder(tee).Decode(&challenge)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
	fmt.Printf("Request body: %s\n", buf.String())
	fmt.Printf("Decoded Ethereum address: %s\n", challenge.EthereumAddress) // log the decoded Ethereum address


    challenge.Nonce = rand.Int() // Generate a random nonce
	fmt.Printf("Generated nonce: %d\n", challenge.Nonce)  // Add this log statement here


    // Save the challenge in the database
    db.Create(&challenge)

	challenges[challenge.EthereumAddress] = strconv.FormatInt(int64(challenge.Nonce), 10) // Store the nonce associated with the Ethereum address


    fmt.Printf("Challenge created: Address=%s, Nonce=%d\n", challenge.EthereumAddress, challenge.Nonce) // log the address and nonce
    
    fmt.Printf("Challenges map: %+v\n", challenges) // log the entire challenges map

    json.NewEncoder(w).Encode(challenge)

}

func LoginWithMetamask(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LoginWithMetamask endpoint hit")
	var data struct {
	  EthereumAddress string `json:"ethereum_address"`
	  Signature       string `json:"signature"`
	}
	
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
	  fmt.Println("Error decoding the request:", err)
	  http.Error(w, err.Error(), http.StatusBadRequest)
	  return
	}

	fmt.Printf("Challenges map before check: %+v\n", challenges) // log the entire challenges map

	fmt.Println("Request decoded successfully")
  
	challenge, ok := challenges[data.EthereumAddress]
	if !ok || challenge == "" {
	  fmt.Println("Invalid challenge")
	  http.Error(w, "Invalid challenge", http.StatusBadRequest)
	  return
	}

	fmt.Println("Challenge fetched successfully")

	// Remove 0x prefix if it exists
	data.Signature = strings.TrimPrefix(data.Signature, "0x")
  
	signatureBytes, err := hex.DecodeString(data.Signature)
	if err != nil {
	  fmt.Println("Error decoding the signature:", err)
	  http.Error(w, "Invalid signature", http.StatusBadRequest)
	  return
	}

	fmt.Println("Signature decoded successfully")
  
	if len(signatureBytes) != 65 {
	  fmt.Println("Invalid signature length")	
	  http.Error(w, "Signature must be 65 bytes long", http.StatusBadRequest)
	  return
	}
  
	// Ethereum uses the `recovery id` (also known as `v`) of 27,28, so we need to subtract 27 from the v included in the signature
	signatureBytes[64] -= 27
  
	message := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(challenge), challenge)
	fmt.Printf("Verifying message: %s\n", message);  // Add this log statement here

	
	fmt.Printf("Verifying message: %s\n", message); // Add this log here
	
	hashedMessage := crypto.Keccak256([]byte(message))
	pubKey, err := crypto.SigToPub(hashedMessage, signatureBytes)

	if err != nil {
	  fmt.Println("Error recovering the public key from the signature:", err)
	  http.Error(w, "Invalid signature", http.StatusBadRequest)
	  return
	}

	fmt.Println("Public key recovered successfully")
  
	recoveredAddress := crypto.PubkeyToAddress(*pubKey).Hex()
	if recoveredAddress != data.EthereumAddress {
	  fmt.Printf("Recovered address: %s\n", recoveredAddress)
	  fmt.Printf("Provided address: %s\n", data.EthereumAddress)
	  fmt.Println("Recovered address does not match the provided address")
	  http.Error(w, "Invalid signature", http.StatusBadRequest)
	  return
	}

	fmt.Println("Recovered address verified successfully")
  
  // At this point, the Ethereum address recovery from the signature was successful,
  // and it matches the Ethereum address sent in the request.

  // Log in the user

  // Assuming that you have a User struct and the EthereumAddress field is unique,
  // we find the user with the EthereumAddress equal to the recoveredAddress.
  var user User
  if err := db.Where("ethereum_address = ?", recoveredAddress).First(&user).Error; err != nil {
	fmt.Println("Error finding the user:", err)
    http.Error(w, "User not found", http.StatusNotFound)
    return
  }

  fmt.Println("User found successfully")

  // Create a new token object, specifying signing method and the claims
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
      "user_id": user.ID,
      "exp":     time.Now().Add(time.Hour * 24).Unix(), // Token expires after 24 hours
  })

  // Sign and get the complete encoded token as a string using the secret
  tokenString, err := token.SignedString([]byte(secretKey))
  if err != nil {
	fmt.Println("Error signing the token:", err)
    http.Error(w, "Could not log in", http.StatusInternalServerError)
    return
  }

  fmt.Println("Token signed successfully")

  // Finally, we send the token to the client
  json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "ethereum_address": recoveredAddress})
  }

