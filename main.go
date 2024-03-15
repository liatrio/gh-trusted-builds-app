package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
)

func main() {
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PONG"))
	})

	http.HandleFunc("/id", func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New()
		_, _ = w.Write([]byte(fmt.Sprintf(`{"id": "%s"}`, id.String())))
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	log.Println("Starting server on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalln("error starting server:", err)
	}
}
