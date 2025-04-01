package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/harr1424/bulletinboard/pkg/utils"
)

type ManagerPageData struct {
	Languages           []string
	Messages            []Message
	CSRF                string
	CreateMessagePath   string
	ManagerPath         string
	AllInvitationsPath  string
	NewInvitationPath   string
	NewTranslationPath  string
	AllTranslationsPath string
	Selected            string
	Error               string
	CurrentUser         string
	UpdatePwdPath       string
	LogoutPath          string
	UserRoles           []string
}

type EditMessage struct {
	Id       string  `json:"id"`
	Content  string  `json:"content"`
	Title    string  `json:"title"`
	ImageUrl *string `json:"image_url,omitempty"`
}

func (h *HandlerWithConfig) renderManager(w http.ResponseWriter, r *http.Request) {
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

	data := ManagerPageData{
		Languages:           []string{"English", "Spanish", "French", "Italian", "Portuguese", "German"},
		CSRF:                csrf.Token(r),
		CreateMessagePath:   h.Config.CreateMessagePath,
		ManagerPath:         h.Config.ManagerPath,
		AllInvitationsPath:  h.Config.AllInvitationsPath,
		NewInvitationPath:   h.Config.NewInvitationPath,
		CurrentUser:         sessionUser,
		UpdatePwdPath:       h.Config.UpdatePwdPath,
		LogoutPath:          h.Config.LogoutPath,
		UserRoles:           sessionRoles,
		NewTranslationPath:  h.Config.NewTranslationPath,
		AllTranslationsPath: h.Config.AllTranslationsPath,
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.Error = "Error processing form"
			log.Printf("Error parsing form: %v", err)

		} else {
			action := r.FormValue("action")
			selectedLang := r.FormValue("language")
			data.Selected = selectedLang

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
			insecure_client := &http.Client{}
			secure_client := &http.Client{Transport: tr}

			switch action {
			case "edit":
				editMsg := EditMessage{
					Id:      r.FormValue("id"),
					Title:   r.FormValue("title"),
					Content: r.FormValue("content"),
				}

				if imgURL := r.FormValue("image_url"); imgURL != "" {
					editMsg.ImageUrl = &imgURL
				}

				jsonData, err := json.Marshal(editMsg)
				if err != nil {
					data.Error = "Error creating edit request"
					log.Printf("Error marshaling edit data: %v", err)
					break
				}

				req, err := http.NewRequest("PATCH",
					h.Config.RemoteServer,
					bytes.NewBuffer(jsonData))
				if err != nil {
					data.Error = "Error creating edit request"
					log.Printf("Error creating edit request: %v", err)
				} else {
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("x-api-key", h.Config.ApiKey)

					resp, err := secure_client.Do(req)
					if err != nil {
						data.Error = "Error updating message"
						log.Printf("Error updating message: %v", err)
					} else {
						defer resp.Body.Close()
						if resp.StatusCode != http.StatusOK {
							data.Error = fmt.Sprintf("Failed to update message. Status: %d", resp.StatusCode)
							log.Printf("Edit request failed with status: %d", resp.StatusCode)
						}
					}
				}

			case "delete":
				messageID := r.FormValue("id")
				if messageID != "" {
					req, err := http.NewRequest("DELETE",
						fmt.Sprintf("%s/%s", h.Config.RemoteServer, messageID),
						nil)
					if err != nil {
						data.Error = "Error creating delete request"
						log.Printf("Error creating delete request: %v", err)
					} else {
						req.Header.Set("x-api-key", h.Config.ApiKey)

						resp, err := secure_client.Do(req)
						if err != nil {
							data.Error = "Error deleting message"
							log.Printf("Error deleting message: %v", err)
						} else {
							defer resp.Body.Close()
							if resp.StatusCode != http.StatusOK {
								data.Error = fmt.Sprintf("Failed to delete message. Status: %d", resp.StatusCode)
								log.Printf("Delete request failed with status: %d", resp.StatusCode)
							}
						}
					}
				}

			default:
				if action != "" {
					log.Printf("Unexpected form action received by manager: %v", action)
				}
			}

			if selectedLang != "" {
				req, err := http.NewRequest("GET",
					fmt.Sprintf("%s/%s", h.Config.RemoteGet, selectedLang),
					nil)
				if err != nil {
					data.Error = "Error creating request"
					log.Printf("Error creating request: %v", err)
				} else {
					resp, err := insecure_client.Do(req)
					if err != nil {
						data.Error = "Error fetching messages"
						log.Printf("Error fetching messages: %v", err)
					} else {
						defer resp.Body.Close()

						if resp.StatusCode == http.StatusOK {
							var messages []Message
							if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
								data.Error = "Error processing response"
								log.Printf("Error decoding response: %v", err)
							} else {
								data.Messages = messages
							}
						} else {
							data.Error = fmt.Sprintf("Server returned status: %d", resp.StatusCode)
						}
					}
				}
			}
		}
	}
	tmpl := template.New("manager.html").Funcs(template.FuncMap{
		"base64": func(data []int) string {
			if len(data) == 0 {
				log.Printf("base64: received empty slice")
				return ""
			}
			// Convert []int to []byte
			bytes := make([]byte, len(data))
			for i, v := range data {
				bytes[i] = byte(v)
			}
			encoded := base64.StdEncoding.EncodeToString(bytes)
			return encoded
		},
		"contains": func(s []string, str string) bool {
			for _, v := range s {
				if v == str {
					return true
				}
			}
			return false
		},
	})

	tmpl, err = tmpl.ParseFiles("templates/manager.html")
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "manager.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}
