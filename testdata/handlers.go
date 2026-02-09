package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// API-ABUSE-001: Missing authentication check - handler exposed directly
func handleGetProfile(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("profile data"))
}

func setupRoutes() {
	http.HandleFunc("/users/profile", handleGetProfile)
}

// API-ABUSE-002: BOLA - user ID from request params used directly in query
func handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("user_id")
	// Direct database lookup without ownership check
	row := db.QueryRow("SELECT * FROM users WHERE id = ?", userID)
	_ = row
}

// API-ABUSE-003: Missing rate limiting on auth endpoint
func setupAuthRoutes() {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/password/reset", handlePasswordReset)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("login"))
}

func handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("reset"))
}

// API-ABUSE-004: Mass assignment - full request body decoded into struct
type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
	Password string `json:"password"`
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	// user.IsAdmin could be set by attacker
	db.Create(&user)
}

// API-ABUSE-005: Verbose error response - internal error details leaked
func handleData(w http.ResponseWriter, r *http.Request) {
	data, err := fetchData()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func handleDetails(w http.ResponseWriter, r *http.Request) {
	result, err := processRequest(r)
	if err != nil {
		msg := fmt.Sprintf("database error: %v", err)
		w.Write([]byte(msg))
		http.Error(w, fmt.Sprintf("internal: %v", err), 500)
	}
	_ = result
}
