package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/harr1424/bulletinboard/pkg/utils"
)

type Translation struct {
	ID           uint32   `json:"id"`
	Name         string   `json:"name"`
	Stage        string   `json:"stage"`
	Translators  []string `json:"translators"`
	DueDate      string   `json:"due_date"`
	FileURL      string   `json:"file_url"`
	LastUpdateBy string   `json:"last_update_by"`
}

type TranslationPageData struct {
	Translations        []Translation
	Translators         []string
	Stages              []string
	CSRF                string
	CreateMessagePath   string
	ManagerPath         string
	AllInvitationsPath  string
	NewInvitationPath   string
	AllTranslationsPath string
	NewTranslationPath  string
	Error               string
	CurrentUser         string
	UpdatePwdPath       string
	LogoutPath          string
	UserRoles           []string
}

type TranslationQuery struct {
	ID          uint32   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Stage       string   `json:"stage,omitempty"`
	Translators []string `json:"translators,omitempty"`
}

type NewTranslationPageData struct {
	Translators         []string
	CSRF                string
	CreateMessagePath   string
	ManagerPath         string
	AllInvitationsPath  string
	NewInvitationPath   string
	AllTranslationsPath string
	NewTranslationPath  string
	Error               string
	CurrentUser         string
	UpdatePwdPath       string
	LogoutPath          string
	UserRoles           []string
	Stages              []string
}

func (h *HandlerWithConfig) renderTranslationsList(w http.ResponseWriter, r *http.Request) {
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

	if !contains(sessionRoles, "view-translations") {
		utils.RenderRedirectPage(w, "You do not have permission to view translations", h.Config.LogoutPath, 5)
		return
	}

	translatorsUrl := fmt.Sprintf("%s/translators", h.Config.Invitations)
	translators := getStringsFromJson(translatorsUrl)

	data := TranslationPageData{
		CSRF:                csrf.Token(r),
		CreateMessagePath:   h.Config.CreateMessagePath,
		ManagerPath:         h.Config.ManagerPath,
		AllInvitationsPath:  h.Config.AllInvitationsPath,
		NewInvitationPath:   h.Config.NewInvitationPath,
		AllTranslationsPath: h.Config.AllTranslationsPath,
		NewTranslationPath:  h.Config.NewTranslationPath,
		Translators:         translators,
		CurrentUser:         sessionUser,
		UpdatePwdPath:       h.Config.UpdatePwdPath,
		LogoutPath:          h.Config.LogoutPath,
		UserRoles:           sessionRoles,
		Stages:              []string{"AITranscription", "AudioProofreading", "GeneralTranslation", "GeneralProofreading", "Adaptation", "VoiceSearch", "Recording", "EnglishEditing", "FinalEditing"},
	}

	client := createSecureClient()

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.Error = fmt.Sprintf("Error processing form: %v", err)
			log.Printf("Error parsing form: %v", err)
		} else {
			action := r.FormValue("action")
			switch action {
			case "delete":
				h.handleDeleteTranslation(client, r, &data)
			case "edit":
				h.handleEditTranslation(client, w, r, &data)
			}
		}
	}

	query := TranslationQuery{}

	if id := r.URL.Query().Get("id"); id != "" {
		query.ID = (uint32(parseInt(id)))
	}
	if name := r.URL.Query().Get("name"); name != "" {
		query.Name = name
	}
	if stage := r.URL.Query().Get("stage"); stage != "" {
		query.Stage = stage
	}
	if translators, ok := r.URL.Query()["translators"]; ok {
		query.Translators = translators
	}

	if query.ID != 0 || query.Name != "" || query.Stage != "" || translators != nil {
		url := fmt.Sprintf("%s/translations", h.Config.Invitations)
		jsonData, err := json.Marshal(query)
		if err != nil {
			data.Error = fmt.Sprintf("Error creating query: %v", err)
			log.Printf("Error marshaling query: %v", err)
			return
		}

		req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonData))
		if err != nil {
			data.Error = fmt.Sprintf("Error creating request: %v", err)
			log.Printf("Error creating request: %v", err)
		} else {
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				data.Error = fmt.Sprintf("Error fetching translations: %v", err)
				log.Printf("Error fetching translations: %v", err)
			} else {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					if err := json.NewDecoder(resp.Body).Decode(&data.Translations); err != nil {
						data.Error = fmt.Sprintf("Error processing response: %v", err)
						log.Printf("Error decoding response: %v", err)
					}
				} else {
					data.Error = fmt.Sprintf("Server returned status: %d", resp.StatusCode)
				}
			}
		}
	}

	tmpl := template.New("translations.html").Funcs(template.FuncMap{
		"derefOr": func(ptr *string, fallback string) string {
			if ptr == nil {
				return fallback
			}
			return *ptr
		},
		"contains": func(s []string, str string) bool {
			for _, v := range s {
				if v == str {
					return true
				}
			}
			return false
		},
		"join": strings.Join,
	})

	tmpl, err = tmpl.ParseFiles("templates/translations.html")
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "translations.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerWithConfig) handleEditTranslation(client *http.Client, w http.ResponseWriter, r *http.Request, data *TranslationPageData) {
	sessionUser := ""
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
	} else {
		http.Redirect(w, r, h.Config.AllInvitationsPath, http.StatusSeeOther)
	}

	t := Translation{
		ID:           uint32(parseInt(r.FormValue("id"))),
		Name:         r.FormValue("name"),
		Stage:        r.FormValue("stage"),
		Translators:  r.Form["translators"],
		DueDate:      r.FormValue("due_date"),
		FileURL:      r.FormValue("file_url"),
		LastUpdateBy: sessionUser,
	}

	jsonData, err := json.Marshal(t)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating edit request: %v", err)
		log.Printf("Error marshaling edit data: %v", err)
		return
	}

	url := fmt.Sprintf("%s/translations", h.Config.Invitations)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		data.Error = fmt.Sprintf("Error creating edit request: %v", err)
		log.Printf("Error creating edit request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		data.Error = fmt.Sprintf("Error updating translation: %v", err)
		log.Printf("Error updating translation: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data.Error = fmt.Sprintf("Failed to update translation. Status: %d", resp.StatusCode)
		log.Printf("Edit request failed with status: %d", resp.StatusCode)
	}
}

func (h *HandlerWithConfig) handleDeleteTranslation(client *http.Client, r *http.Request, data *TranslationPageData) {
	id := r.FormValue("id")
	if id == "" {
		data.Error = "No translation ID provided for deletion"
		return
	}

	url := fmt.Sprintf("%s/translations/%s", h.Config.Invitations, id)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating delete request: %v", err)
		log.Printf("Error creating delete request: %v", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		data.Error = fmt.Sprintf("Error deleting translation: %v", err)
		log.Printf("Error deleting translation: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data.Error = fmt.Sprintf("Failed to delete translation. Status: %d", resp.StatusCode)
		log.Printf("Delete request failed with status: %d", resp.StatusCode)
	}
}

func (h *HandlerWithConfig) renderNewTranslationPage(w http.ResponseWriter, r *http.Request) {
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

	if !contains(sessionRoles, "edit-translations") {
		utils.RenderRedirectPage(w, "You do not have permission to create and edit translations", h.Config.LogoutPath, 5)
		return
	}

	translatorsUrl := fmt.Sprintf("%s/translators", h.Config.Invitations)
	translators := getStringsFromJson(translatorsUrl)

	data := NewTranslationPageData{
		CSRF:                csrf.Token(r),
		CreateMessagePath:   h.Config.CreateMessagePath,
		ManagerPath:         h.Config.ManagerPath,
		AllInvitationsPath:  h.Config.AllInvitationsPath,
		NewInvitationPath:   h.Config.NewInvitationPath,
		AllTranslationsPath: h.Config.AllTranslationsPath,
		NewTranslationPath:  h.Config.NewTranslationPath,
		Translators:         translators,
		CurrentUser:         sessionUser,
		UpdatePwdPath:       h.Config.UpdatePwdPath,
		LogoutPath:          h.Config.LogoutPath,
		UserRoles:           sessionRoles,
		Stages:              []string{"AITranscription", "AudioProofreading", "GeneralTranslation", "GeneralProofreading", "Adaptation", "VoiceSearch", "Recording", "EnglishEditing", "FinalEditing"},
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.Error = fmt.Sprintf("Error processing form: %v", err)
			log.Printf("Error parsing form: %v", err)
		} else {
			client := createSecureClient()
			action := r.FormValue("action")

			switch action {
			case "create":
				h.handleCreateTranslation(client, w, r, &data)

			case "add_translator":
				newInstructor := r.FormValue("new_translator")
				if newInstructor == "" {
					data.Error = "Translator name cannot be empty"
					break
				}

				resp, err := client.Post(
					fmt.Sprintf("%s/translators/%s", h.Config.Invitations, url.PathEscape(newInstructor)),
					"text/plain",
					nil,
				)
				if err != nil {
					data.Error = fmt.Sprintf("Failed to add translator: %v", err)
					log.Printf("Error adding translator: %v", err)
				} else {
					resp.Body.Close()
					http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
					return
				}

			case "delete_translator":
				instructor := r.FormValue("translator_to_delete")
				if instructor == "" {
					data.Error = "No translator selected for deletion"
					break
				}

				req, _ := http.NewRequest(
					http.MethodDelete,
					fmt.Sprintf("%s/translators/%s", h.Config.Invitations, url.PathEscape(instructor)),
					nil,
				)
				resp, err := client.Do(req)
				if err != nil {
					data.Error = fmt.Sprintf("Failed to delete translator: %v", err)
					log.Printf("Error deleting translator: %v", err)
				} else {
					resp.Body.Close()
					http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
					return
				}

			default:
				data.Error = fmt.Sprintf("Unknown action: %s", action)
				log.Printf("Unknown form action: %s", action)
			}
		}
	}

	tmpl := template.New("create-translation.html").Funcs(template.FuncMap{
		"contains": func(s []string, str string) bool {
			for _, v := range s {
				if v == str {
					return true
				}
			}
			return false
		},
	})

	tmpl, err = tmpl.ParseFiles("templates/create-translation.html")
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "create-translation.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerWithConfig) handleCreateTranslation(client *http.Client, w http.ResponseWriter, r *http.Request, data *NewTranslationPageData) {
	sessionUser := ""
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
	} else {
		http.Redirect(w, r, h.Config.AllInvitationsPath, http.StatusSeeOther)
	}

	t := Translation{
		ID:           uint32(parseInt(r.FormValue("id"))),
		Name:         r.FormValue("name"),
		Stage:        r.FormValue("stage"),
		Translators:  r.Form["translators"],
		DueDate:      r.FormValue("due_date"),
		FileURL:      r.FormValue("file_url"),
		LastUpdateBy: sessionUser,
	}

	jsonData, err := json.Marshal(t)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating translation request: %v", err)
		log.Printf("Error marshaling new translation data: %v", err)
		return
	}

	url := fmt.Sprintf("%s/translations", h.Config.Invitations)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		data.Error = fmt.Sprintf("Error creating translation request: %v", err)
		log.Printf("Error creating translation request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating translation: %v", err)
		log.Printf("Error creating translation: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		data.Error = fmt.Sprintf("Failed to create translation. Status: %d", resp.StatusCode)
		log.Printf("Create request failed with status: %d", resp.StatusCode)
	}
}
