package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"golang/auth"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func errorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprint(err)})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func getHome(w http.ResponseWriter, r *http.Request) {
	print(r.URL.Path)
	http.ServeFile(w, r, "web/templates/index.html")
}

// getConfigParameters retrieves the configuration parameters
func getConfigParameters(auth *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		ticket, err := auth.GetTicket()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		timestamp := time.Now().Unix() * 1000
		nonceStr := "13oEviLbrTo458A3NjrOwS70oTOXVOAm"
		verifyStr := fmt.Sprintf("jsapi_ticket=%s&noncestr=%s&timestamp=%d&url=%s", ticket, nonceStr, timestamp, url)
		h := sha1.New()
		io.WriteString(h, verifyStr)
		signature := fmt.Sprintf("%x", h.Sum(nil))

		response := map[string]interface{}{
			"appid":     auth.AppID,
			"signature": signature,
			"noncestr":  nonceStr,
			"timestamp": timestamp,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	feishuHost := os.Getenv("FEISHU_HOST")
	appID := os.Getenv("APP_ID")
	appSecret := os.Getenv("APP_SECRET")

	auth := auth.NewAuth(feishuHost, appID, appSecret)

	mux := http.NewServeMux()
	mux.HandleFunc("/", getHome)
	mux.HandleFunc("/get_config_parameters", getConfigParameters(auth))

	fs := http.FileServer(http.Dir("web/public"))
	mux.Handle("/public/", http.StripPrefix("/public", fs))

	log.Println("Starting server on :3000")
	err = http.ListenAndServe(":3000", errorHandler(mux))
	if err != nil {
		log.Fatal(err)
	}
}
