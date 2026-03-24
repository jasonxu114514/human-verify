package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"human-verify-web/internal/captcha"
)

func main() {
	addr := getenv("ADDR", ":8080")
	staticDir := getenv("STATIC_DIR", filepath.Join(".", "static"))

	service, err := captcha.NewService(captcha.Config{
		AssetsDir:           filepath.Join(staticDir, "assets"),
		AssetURLPrefix:      "/static/assets/",
		Width:               320,
		Height:              180,
		PieceSize:           54,
		SessionTTL:          2 * time.Minute,
		AttemptCookieSecret: os.Getenv("ATTEMPT_COOKIE_SECRET"),
		PowDifficulty:       getenvInt("POW_DIFFICULTY", 3),
	})
	if err != nil {
		log.Fatalf("init captcha service: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	mux.HandleFunc("/api/captcha/new", service.HandleNew)
	mux.HandleFunc("/api/captcha/verify", service.HandleVerify)
	mux.HandleFunc("/api/captcha/panel/", service.HandlePanel)
	mux.HandleFunc("/api/captcha/piece/", service.HandlePiece)

	server := &http.Server{
		Addr:              addr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("slider captcha server listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func getenvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
