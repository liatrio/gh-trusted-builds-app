package main

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

func main() {
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("PONG"))
	})

	http.HandleFunc("/id", func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New()
		w.Write([]byte(fmt.Sprintf(`{"id": "%s"}`, id.String())))
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
