package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

const SessionName = "session-name"

func (h *HandlerWithConfig) renderLogin(w http.ResponseWriter, r *http.Request, errorMsg string, csrfToken string) {
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	data := struct {
		LoginPath string
		Error     string
		CSRF      string
	}{
		LoginPath: h.Config.LoginPath,
		Error:     errorMsg,
		CSRF:      csrfToken,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerWithConfig) clearSession(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     SessionName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, cookie)
}

func (h *HandlerWithConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	h.clearSession(w, r)

	ip := r.RemoteAddr
	limiter := h.RateLimiter.GetLimiter(ip)
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded - slow down -", http.StatusTooManyRequests)
		return
	}

	switch r.Method {
	case http.MethodGet:
		token := csrf.Token(r)
		h.renderLogin(w, r, "", token)

	case http.MethodPost:
		username := sanitizeInput(r.FormValue("username"))
		password := sanitizeInput(r.FormValue("password"))

		if len(username) == 0 || len(username) > 24 || len(password) == 0 || len(password) > 64 {
			time.Sleep(time.Second)
			h.renderLogin(w, r, "Invalid credentials", csrf.Token(r))
			return
		}

		result, err := login(h.Config.AuthPath, username, password)
		if err != nil {
			time.Sleep(time.Second)
			h.renderLogin(w, r, fmt.Sprintf("Error: %v\n %v", err.Error(), result), csrf.Token(r))
			return
		}
		if result.Message == "Login successful" {
			roles, err := getRoles(h.Config.AuthPath, username)
			if err != nil {
				h.renderLogin(w, r, fmt.Sprintf("Error retrieving roles: %s", err.Error()), csrf.Token(r))
				return
			}
			log.Println(fmt.Sprintf("Found the following roles for %s: %v", username, roles))

			session := sessions.NewSession(h.Store, SessionName)
			session.Values["authenticated"] = true
			session.Values["created"] = time.Now().Unix()
			session.Values["user"] = username
			session.Values["roles"] = roles
			session.Options = &sessions.Options{
				Path:     "/",
				MaxAge:   60 * 60 * 24,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			}

			if err := h.Store.Save(r, w, session); err != nil {
				log.Printf("Error saving new session: %v", err)
				h.renderLogin(w, r, "Error creating session", csrf.Token(r))
				return
			}

			log.Printf("Login successful for user: %s", username)
			http.Redirect(w, r, h.Config.AllInvitationsPath, http.StatusSeeOther)
			return
		}

		time.Sleep(time.Second)
		h.renderLogin(w, r, "Invalid credentials", csrf.Token(r))
		return

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Message string `json:"message"`
}

func sanitizeInput(input string) string {
	// Remove control characters
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, input)
}

func login(baseURL, username, password string) (*LoginResponse, error) {
	loginReq := LoginRequest{
		Username: username,
		Password: password,
	}

	jsonData, err := json.Marshal(loginReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	url := fmt.Sprintf("%slogin", baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var loginResp LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return &loginResp, fmt.Errorf("login failed: %s", loginResp.Message)
	}

	return &loginResp, nil
}

func getRoles(baseURL, username string) ([]string, error) {
	url := fmt.Sprintf("%sroles", baseURL)

	user := map[string]string{"username": username}
	jsonData, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP error: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var roles []string
	err = json.Unmarshal(body, &roles)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return roles, nil
}

func (h *HandlerWithConfig) logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.Store.Get(r, SessionName)
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Error getting session for deletion", http.StatusInternalServerError)
		return
	}

	sessionUser := ""
	if username, ok := session.Values["user"].(string); ok {
		sessionUser = username
	} else {
		log.Printf("Error getting username from session during logout: %v", err)
	}
	// Clear session values
	session.Values["authenticated"] = false
	delete(session.Values, "created")

	// Expire the session cookie by setting MaxAge to a negative value
	session.Options.MaxAge = -1
	session.Options.Path = "/"
	session.Options.HttpOnly = true
	session.Options.Secure = true
	session.Options.SameSite = http.SameSiteStrictMode

	if err := h.Store.Save(r, w, session); err != nil {
		log.Printf("Error saving expired session: %v", err)
		http.Error(w, "Error logging out", http.StatusInternalServerError)
		return
	}

	log.Println(fmt.Sprintf("User %s logged out", sessionUser))
	http.Redirect(w, r, h.Config.LoginPath, http.StatusSeeOther) // Redirect to login page
}
