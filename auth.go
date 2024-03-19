package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

func AuthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		//  Basic Auth credentials
		username, _, ok := r.BasicAuth()
		if !ok { // If Basic Auth fails, parse JSON payload
			var creds struct {
				Username string `json:"username"`
				Password string `json:"password"` //
			}
			if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
				// parsing JSON also fails, return an error
				http.Error(w, "Invalid authentication method!", http.StatusBadRequest)
				return
			}
			username = creds.Username
		}

		expired, _ := strconv.ParseBool(r.URL.Query().Get("expired"))
		signingKey, kid, err := fetchSigningKey(db, expired)
		if err != nil {
			http.Error(w, "Failed to fetch key", http.StatusInternalServerError)
			return
		}

		//  JWT creation
		claims := jwt.MapClaims{
			"iss": "jwks-server",
			"sub": username, //
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid

		tokenString, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "Failed to sign token", http.StatusInternalServerError)
			return
		}

		// Return JWT in response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

func fetchSigningKey(db *sql.DB, expired bool) (*rsa.PrivateKey, string, error) {
	var keyPEM []byte
	var kid int // Use int for kid schema
	var err error

	if expired {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp <= ?", time.Now().Unix()).Scan(&kid, &keyPEM)
	} else {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&kid, &keyPEM)
	}

	if err != nil {
		return nil, "", err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, "", errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}

	return privateKey, strconv.Itoa(kid), nil
}

func fetchKey(db *sql.DB, expired bool) (*rsa.PrivateKey, error) {
	var keyPEM []byte
	var err error

	if expired {
		err = db.QueryRow("SELECT key FROM keys WHERE exp <= ?", time.Now().Unix()).Scan(&keyPEM)
	} else {
		err = db.QueryRow("SELECT key FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&keyPEM)
	}

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
