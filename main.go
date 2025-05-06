// Based on: https://github.com/altcha-org/altcha-starter-go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/altcha-org/altcha-lib-go"
)

var (
	altchaHMACKey       = getEnv("ALTCHA_HMAC_KEY", "MY_ALTCHA_HMAC_KEY")
	serverPort          = getEnv("PORT", "3000")
	expireTimeInMins    = getEnvAsInt("EXPIRE_TIME_IN_MINS", 5)
	cacheCleanupMinutes = getEnvAsInt("CACHE_CLEAN_INTERVAL_MINS", 15)
)

// Struct to store solution metadata
type cachedSolution struct {
	expiresAt time.Time
}

type healthPayload struct {
	Status        string `json:"status"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	MemAllocMB    uint64 `json:"memAllocMB"`
	MemSysMB      uint64 `json:"memSysMB"`
	NumGoroutine  int    `json:"goroutines"`
}

var startTime = time.Now()

var (
	usedSolutions = make(map[string]cachedSolution)
	cacheMutex    = sync.Mutex{}
)

func main() {
	go startCacheCleaner()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/challenge", challengeHandler)
	mux.HandleFunc("/verify", verifyHandler)

	log.Printf("ALTCHA server is up and running on port %s\n", serverPort)
	handler := loggingMiddleware(corsMiddleware(mux))
	if err := http.ListenAndServe(":"+serverPort, handler); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	uptime := time.Since(startTime).Seconds()

	payload := healthPayload{
		Status:        "ok",
		UptimeSeconds: int64(uptime),
		MemAllocMB:    m.Alloc / 1024 / 1024, // Convert bytes to MB
		MemSysMB:      m.Sys / 1024 / 1024,   // Convert bytes to MB
		NumGoroutine:  runtime.NumGoroutine(),
	}

	writeJSON(w, payload)
}

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

	cacheMutex.Lock()
	if entry, found := usedSolutions[payload]; found {
		if time.Now().Before(entry.expiresAt) {
			cacheMutex.Unlock()
			writeError(w, "Replay detected: CAPTCHA already used")
			return
		}
	}
	cacheMutex.Unlock()

	verified, err := altcha.VerifySolution(payload, altchaHMACKey, true)
	if err != nil || !verified {
		if err != nil {
			log.Printf("Altcha verification error: %v", err)
			writeError(w, "Verification error: "+err.Error())
		} else {
			log.Println("Altcha verification failed: token is invalid or expired")
			writeError(w, "Invalid or expired Altcha token")
		}
		return
	}

	// Add to cache with expiresAt
	cacheMutex.Lock()
	usedSolutions[payload] = cachedSolution{
		expiresAt: time.Now().Add(time.Duration(expireTimeInMins) * time.Minute),
	}
	cacheMutex.Unlock()

	writeJSON(w, map[string]bool{"success": true})
}

// Clean up expired entries from cache
func startCacheCleaner() {
	ticker := time.NewTicker(time.Duration(cacheCleanupMinutes) * time.Minute)
	for range ticker.C {
		now := time.Now()
		log.Println("Cache cleaner started")
		removed := 0

		cacheMutex.Lock()
		for key, entry := range usedSolutions {
			if entry.expiresAt.Before(now) {
				delete(usedSolutions, key)
				removed++
			}
		}
		remaining := len(usedSolutions)
		cacheMutex.Unlock()

		log.Printf("Cache cleaner finished - removed %d expired solution(s), %d remaining in cache\n", removed, remaining)
	}
}

// Utility functions
func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	valStr := getEnv(key, "")
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return fallback
	}
	return val
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
		log.Printf("%s %s from %s - %v",
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

func writeError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"message": message,
	})
}
