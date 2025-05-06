// Based on: https://github.com/altcha-org/altcha-starter-go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/altcha-org/altcha-lib-go"
)

var altchaHMACKey = getEnv("ALTCHA_HMAC_KEY", "MY_ALTCHA_HMAC_KEY")
var serverPort = getEnv("PORT", "3000")
var expireTimeInMins = func() int {
	val, err := strconv.Atoi(getEnv("EXPIRE_TIME_IN_MINS", "5"))
	if err != nil {
		log.Printf("Invalid EXPIRE_TIME_IN_MINS value, falling back to 5")
		return 5
	}
	return val
}()

// In-memory cache for preventing replay attacks
var (
	usedSolutions = make(map[string]time.Time)
	cacheMutex    = sync.Mutex{}
	cacheTTL      = 3 * time.Hour
)

func main() {
	go startCacheCleaner()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/challenge", challengeHandler)
	mux.HandleFunc("/verify", verifyHandler)

	fmt.Printf("ALTCHA server is running on port %s\n", serverPort)
	handler := loggingMiddleware(corsMiddleware(mux))
	if err := http.ListenAndServe(":"+serverPort, handler); err != nil {
		log.Fatal(err)
	}
}

// /health endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"status": "ok",
	})
}

// /challenge endpoint
func challengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	expiresAt := time.Now().Add(time.Duration(expireTimeInMins) * time.Minute)

	challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
		HMACKey:   altchaHMACKey,
		MaxNumber: 50000,
		Expires:   &expiresAt,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create challenge: %s", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, challenge)
}

// /verify endpoint
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payload := r.FormValue("altcha")
	if payload == "" {
		http.Error(w, "Altcha payload missing", http.StatusBadRequest)
		return
	}

	// Check replay cache
	cacheMutex.Lock()
	if _, found := usedSolutions[payload]; found {
		cacheMutex.Unlock()
		http.Error(w, "Replay detected: CAPTCHA already used", http.StatusForbidden)
		return
	}
	cacheMutex.Unlock()

	verified, err := altcha.VerifySolution(payload, altchaHMACKey, true)
	if err != nil || !verified {
		if err != nil {
			log.Printf("Altcha verification error: %v", err)
		} else {
			log.Println("Altcha verification failed: token is invalid or expired")
		}
		http.Error(w, "Invalid Altcha payload", http.StatusBadRequest)
		return
	}

	// Add to cache
	cacheMutex.Lock()
	usedSolutions[payload] = time.Now()
	cacheMutex.Unlock()

	writeJSON(w, map[string]interface{}{
		"success": true,
	})
}

// Clean up old entries from cache every 15 minutes
func startCacheCleaner() {
	ticker := time.NewTicker(15 * time.Minute)
	for range ticker.C {
		cacheMutex.Lock()
		for k, t := range usedSolutions {
			if time.Since(t) > cacheTTL {
				delete(usedSolutions, k)
			}
		}
		cacheMutex.Unlock()
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Proceed with request
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		log.Printf("[%s] %s %s from %s - %v",
			start.Format(time.RFC3339),
			r.Method,
			r.URL.Path,
			getRealIP(r),
			duration,
		)
	})
}

func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // fallback, possibly with port
	}
	return host
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
	}
}
