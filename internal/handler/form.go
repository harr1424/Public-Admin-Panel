package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/harr1424/bulletinboard/pkg/utils"
)

const maxUploadSize = 10 << 20

var allowedFileTypes = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
}

type Message struct {
	Id            string  `json:"id"`
	Lang          string  `json:"lang"`
	Expires       string  `json:"expires"`
	Title         string  `json:"title"`
	Content       string  `json:"content"`
	ImageUrl      *string `json:"image_url,omitempty"`
	ImageData     []int   `json:"image_data,omitempty"`      // base64 encoded image
	ImageMimeType *string `json:"image_mime_type,omitempty"` // example:  "image/jpeg"
}

type MessageFormData struct {
	Languages           []string
	Durations           []string
	SubmitPath          string
	CreateMessagePath   string
	ManagerPath         string
	AllInvitationsPath  string
	NewInvitationPath   string
	NewTranslationPath  string
	AllTranslationsPath string
	CSRF                string
	Error               string
	UpdatePwdPath       string
	LogoutPath          string
	CurrentUser         string
	UserRoles           []string
}

func (h *HandlerWithConfig) renderForm(w http.ResponseWriter, r *http.Request) {
	sessionUser := ""
	sessionRoles := make([]string, 0)
	session, err := h.Store.Get(r, SessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if authenticated, ok := session.Values["authenticated"].(bool); ok && authenticated {
		if username, ok := session.Values["user"].(string); ok {
			sessionUser = username
		} else {
			http.Error(w, "Error getting current user", http.StatusInternalServerError)
		}

		if roles, ok := session.Values["roles"].([]string); ok {
			sessionRoles = append(sessionRoles, roles...)
		} else {
			http.Error(w, "Error getting user roles", http.StatusInternalServerError)
		}
	} else {
		http.Redirect(w, r, h.Config.AllInvitationsPath, http.StatusSeeOther)
	}

	if !contains(sessionRoles, "send-messages") {
		utils.RenderRedirectPage(w, "You do not have permission to send or manage messages to app users.", h.Config.AllInvitationsPath, 5)
		return
	}

	data := MessageFormData{
		Languages:           []string{"English", "Spanish", "French", "Italian", "Portuguese", "German"},
		Durations:           []string{"Now", "Hour", "Day", "Week", "Quarter", "Year"},
		SubmitPath:          h.Config.SubmitMessagePath,
		CreateMessagePath:   h.Config.CreateMessagePath,
		ManagerPath:         h.Config.ManagerPath,
		CSRF:                csrf.Token(r),
		AllInvitationsPath:  h.Config.AllInvitationsPath,
		NewInvitationPath:   h.Config.NewInvitationPath,
		CurrentUser:         sessionUser,
		UpdatePwdPath:       h.Config.UpdatePwdPath,
		LogoutPath:          h.Config.LogoutPath,
		UserRoles:           sessionRoles,
		NewTranslationPath:  h.Config.NewTranslationPath,
		AllTranslationsPath: h.Config.AllTranslationsPath,
	}

	tmpl := template.New("message.html").Funcs(template.FuncMap{
		"contains": func(s []string, str string) bool {
			for _, v := range s {
				if v == str {
					return true
				}
			}
			return false
		},
	})

	tmpl, err = tmpl.ParseFiles("templates/message.html")
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "message.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerWithConfig) handleSubmit(w http.ResponseWriter, r *http.Request) {
	sessionRoles := make([]string, 0)
	session, err := h.Store.Get(r, SessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if authenticated, ok := session.Values["authenticated"].(bool); ok && authenticated {
		if roles, ok := session.Values["roles"].([]string); ok {
			sessionRoles = append(sessionRoles, roles...)
		} else {
			http.Error(w, "Error getting user roles", http.StatusInternalServerError)
		}
	} else {
		http.Redirect(w, r, h.Config.AllInvitationsPath, http.StatusSeeOther)
	}

	if !contains(sessionRoles, "send-messages") {
		utils.RenderRedirectPage(w, "You do not have permission to send or manage messages to app users.", h.Config.AllInvitationsPath, 5)
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	err = r.ParseMultipartForm(maxUploadSize)
	if err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		http.Error(w, "Error processing form", http.StatusBadRequest)
		return
	}

	message := Message{
		Lang:     r.FormValue("language"),
		Expires:  r.FormValue("duration"),
		Title:    r.FormValue("title"),
		Content:  r.FormValue("message"),
		ImageUrl: utils.StringPointer(r.FormValue("image_url")),
	}

	file, header, err := r.FormFile("image")
	if err == nil && file != nil {
		defer file.Close()

		imageData, mimeType, err := processImage(file, header)
		if err != nil {
			log.Printf("Error processing image: %v", err)
			utils.RenderRedirectPage(w, fmt.Sprintf("Error processing image: %v", err), h.Config.CreateMessagePath, 5)
			return
		}

		jsonSafeImageData := make([]int, len(imageData))
		for i, b := range imageData {
			jsonSafeImageData[i] = int(b)
		}

		message.ImageData = jsonSafeImageData
		message.ImageMimeType = &mimeType
		message.ImageUrl = nil
	}

	log.Printf("Submitting message with title: %s", message.Title)
	jsonData, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshalling JSON: %v", err)
		http.Error(w, "Error processing request", http.StatusInternalServerError)
		return
	}
	log.Printf("Size of JSON payload: %d bytes", len(jsonData))

	req, err := http.NewRequest("POST", h.Config.RemoteServer, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	// sensitive headers removed for public project demo

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
		log.Printf("Error sending request: %v", err)
		http.Error(w, "Error sending request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("Response status: %d, body: %s", resp.StatusCode, string(body))

	if resp.StatusCode == http.StatusOK {
		utils.RenderRedirectPage(w, "Message sent successfully!", h.Config.CreateMessagePath, 5)
	} else {
		utils.RenderRedirectPage(w, fmt.Sprintf("Failed to send message. Status code: %d", resp.StatusCode), h.Config.CreateMessagePath, 5)
	}
}

func getMimeType(ext string) string {
	switch ext {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

func processImage(file multipart.File, header *multipart.FileHeader) ([]byte, string, error) {
	if header.Size > maxUploadSize {
		return nil, "", fmt.Errorf("file size exceeds maximum limit of %d bytes", maxUploadSize)
	}

	ext := filepath.Ext(header.Filename)
	if !allowedFileTypes[ext] {
		return nil, "", fmt.Errorf("invalid file type. Allowed types: jpg, jpeg, png, gif")
	}

	buffer := make([]byte, header.Size)
	if _, err := file.Read(buffer); err != nil {
		return nil, "", fmt.Errorf("error reading file: %v", err)
	}

	mimeType := http.DetectContentType(buffer)
	if !strings.HasPrefix(mimeType, "image/") {
		return nil, "", fmt.Errorf("invalid file type. Detected MIME type: %s", mimeType)
	}

	return buffer, getMimeType(ext), nil
}
