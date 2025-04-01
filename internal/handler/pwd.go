package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
)

func (h *HandlerWithConfig) renderPwd(w http.ResponseWriter, r *http.Request, errorMsg string, csrfToken string) {
	tmpl, err := template.ParseFiles("templates/pwd.html")
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	data := struct {
		UpdatePwdPath string
		Error         string
		CSRF          string
	}{
		UpdatePwdPath: h.Config.UpdatePwdPath,
		Error:         errorMsg,
		CSRF:          csrfToken,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerWithConfig) updateHandler(w http.ResponseWriter, r *http.Request) {
	h.clearSession(w, r)

	ip := r.RemoteAddr
	limiter := h.RateLimiter.GetLimiter(ip)
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded - slow down - easy does it!", http.StatusTooManyRequests)
		return
	}

	switch r.Method {
	case http.MethodGet:
		token := csrf.Token(r)
		h.renderPwd(w, r, "", token)

	case http.MethodPost:
		username := sanitizeInput(r.FormValue("username"))
		password := sanitizeInput(r.FormValue("password"))
		password_confirm := sanitizeInput(r.FormValue("password_confirm"))

		if strings.Compare(password, password_confirm) != 0 {
			h.renderPwd(w, r, "Passwords must match", csrf.Token(r))
			return
		}

		if len(username) == 0 || len(username) > 24 || len(password) == 0 || len(password) > 64 {
			h.renderPwd(w, r, "Invalid credentials: password must be between 1 and 64 characters, username must already exist", csrf.Token(r))
			return
		}

		result, err := update(h.Config.AuthPath, username, password)
		if err != nil {
			h.renderPwd(w, r, err.Error(), csrf.Token(r))
		}
		if result.Message == "Update successful" {
			log.Printf("Pwd update successful for user: %s", username)
			http.Redirect(w, r, h.Config.LogoutPath, http.StatusSeeOther)
			return
		}

		h.renderPwd(w, r, result.Message, csrf.Token(r))
		return

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type UpdateRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	PasswordConfirm string `json:"password_confirm"`
}

type UodateResponse struct {
	Message string `json:"message"`
}

func update(baseURL, username, password string) (*UodateResponse, error) {
	updateReq := UpdateRequest{
		Username: username,
		Password: password,
	}

	jsonData, err := json.Marshal(updateReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	url := fmt.Sprintf("%supdate", baseURL)
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

	var updateResp UodateResponse
	if err := json.NewDecoder(resp.Body).Decode(&updateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &updateResp, fmt.Errorf("login failed: %s", updateResp.Message)
	}

	return &updateResp, nil
}
