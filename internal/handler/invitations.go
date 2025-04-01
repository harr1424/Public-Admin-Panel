package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/csrf"
	"github.com/harr1424/bulletinboard/pkg/utils"
)

type InvitePageData struct {
	Languages           []string
	Engagements         []Engagement
	CSRF                string
	CreateMessagePath   string
	ManagerPath         string
	AllInvitationsPath  string
	NewInvitationPath   string
	NewTranslationPath  string
	AllTranslationsPath string
	Selected            string
	Error               string
	Hosts               []string
	Instructors         []string
	ActivityTypes       []string
	CurrentUser         string
	UpdatePwdPath       string
	LogoutPath          string
	UserRoles           []string
}

type EngagementQuery struct {
	Language     *string `json:"language,omitempty"`
	Number       *string `json:"number,omitempty"`
	ActivityType *string `json:"activity_type,omitempty"`
	Instructor   *string `json:"instructor,omitempty"`
	Host         *string `json:"host,omitempty"`
	Date         *string `json:"date,omitempty"`
	Status       *string `json:"status,omitempty"`
	HostStatus   *string `json:"host_status,omitempty"`
	FlyerStatus  *string `json:"flyer_status,omitempty"`
}

type Engagement struct {
	ID            string  `json:"id"`
	Instructor    string  `json:"instructor"`
	Host          string  `json:"host"`
	Date          string  `json:"date"`
	Language      string  `json:"language"`
	Title         string  `json:"title"`
	Part          int     `json:"part"`
	NumParts      int     `json:"num_parts"`
	Status        string  `json:"status"`
	HostStatus    *string `json:"host_status,omitempty"`
	FlyerStatus   *string `json:"flyer_status,omitempty"`
	Notes         *string `json:"notes,omitempty"`
	Number        *string `json:"number,omitempty"`
	ActivityType  *string `json:"activity_type,omitempty"`
	LastUpdatedBy *string `json:"last_updated_by,omitempty"`
}

type NewEngagement struct {
	Instructor    string `json:"instructor"`
	Host          string `json:"host"`
	Date          string `json:"date"`
	Language      string `json:"language"`
	Title         string `json:"title"`
	Part          int    `json:"part"`
	NumParts      int    `json:"num_parts"`
	Status        string `json:"status"`
	HostStatus    string `json:"host_status"`
	FlyerStatus   string `json:"flyer_status"`
	Notes         string `json:"notes"`
	Number        string `json:"number"`
	ActivityType  string `json:"activity_type"`
	LastUpdatedBy string `json:"last_updated_by"`
}

func getStringsFromJson(url string) []string {
	client := createSecureClient()

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error getting strings: %v", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var strings []string
		if err := json.NewDecoder(resp.Body).Decode(&strings); err != nil {
			log.Printf("Error deserializing strings from json: %v", err)
			return nil
		}
		return strings
	}
	log.Printf("Unexpected status code: %d", resp.StatusCode)
	return nil
}

func (q *EngagementQuery) hasSearchCriteria() bool {
	return q.Language != nil || q.Number != nil || q.Date != nil ||
		q.ActivityType != nil || q.Instructor != nil || q.Host != nil ||
		q.Status != nil || q.HostStatus != nil || q.FlyerStatus != nil
}

func (h *HandlerWithConfig) renderEngagementsList(w http.ResponseWriter, r *http.Request) {
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

	if !contains(sessionRoles, "view-invites") {
		utils.RenderRedirectPage(w, "You do not have permission to view invitations", h.Config.LogoutPath, 5)
		return
	}

	hostsUrl := fmt.Sprintf("%s/hosts", h.Config.Invitations)
	hosts := getStringsFromJson(hostsUrl)

	instructorsUrl := fmt.Sprintf("%s/instructors", h.Config.Invitations)
	instructors := getStringsFromJson(instructorsUrl)

	data := InvitePageData{
		Languages:          []string{"Any", "English", "Spanish", "French", "Italian", "Portuguese", "German", "Persian"},
		CSRF:               csrf.Token(r),
		CreateMessagePath:  h.Config.CreateMessagePath,
		ManagerPath:        h.Config.ManagerPath,
		AllInvitationsPath: h.Config.AllInvitationsPath,
		NewInvitationPath:  h.Config.NewInvitationPath,
		Hosts:              hosts,
		Instructors:        instructors,
		ActivityTypes: []string{"Monologue", "Dialog Format", "Interview", "Thematic Round Table", "Open Mic",
			"Open Topic Gnostic Talk", "Multi-institutional Radio Activity", "SAW Audio Translation", "Easter Special",
			"Christmas Special", "Pre-recorded Translation", "Pre-Recorded Activity", "Bilingual Activity", "Practice",
			"Pre-recorded Practice"},
		CurrentUser:         sessionUser,
		UpdatePwdPath:       h.Config.UpdatePwdPath,
		LogoutPath:          h.Config.LogoutPath,
		UserRoles:           sessionRoles,
		NewTranslationPath:  h.Config.NewTranslationPath,
		AllTranslationsPath: h.Config.AllTranslationsPath,
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
				h.handleDelete(client, r, &data)
			case "edit":
				h.handleEdit(client, w, r, &data)
			}
		}
	}

	query := EngagementQuery{}

	// Only add optional parameters if they're not empty
	if lang := r.URL.Query().Get("language"); lang != "" {
		query.Language = &lang
		data.Selected = lang
	}

	if num := r.URL.Query().Get("number"); num != "" {
		query.Number = &num
	}
	if actType := r.URL.Query().Get("activity_type"); actType != "" {
		query.ActivityType = &actType
	}
	if inst := r.URL.Query().Get("instructor"); inst != "" {
		query.Instructor = &inst
	}
	if host := r.URL.Query().Get("host"); host != "" {
		query.Host = &host
	}
	if date := r.URL.Query().Get("date"); date != "" {
		query.Date = &date
	}
	if status := r.URL.Query().Get("status"); status != "" {
		query.Status = &status
	}
	if hostStatus := r.URL.Query().Get("host_status"); hostStatus != "" {
		query.HostStatus = &hostStatus
	}
	if flyerStatus := r.URL.Query().Get("flyer_status"); flyerStatus != "" {
		query.FlyerStatus = &flyerStatus
	}

	if query.hasSearchCriteria() {
		url := fmt.Sprintf("%s/engs", h.Config.Invitations)
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
				data.Error = fmt.Sprintf("Error fetching engagements: %v", err)
				log.Printf("Error fetching engagements: %v", err)
			} else {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					if err := json.NewDecoder(resp.Body).Decode(&data.Engagements); err != nil {
						data.Error = fmt.Sprintf("Error processing response: %v", err)
						log.Printf("Error decoding response: %v", err)
					}
				} else {
					data.Error = fmt.Sprintf("Server returned status: %d", resp.StatusCode)
				}
			}
		}
	}

	tmpl := template.New("engagements-list.html").Funcs(template.FuncMap{
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
	})

	tmpl, err = tmpl.ParseFiles("templates/engagements-list.html")
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "engagements-list.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerWithConfig) renderCreateEngagement(w http.ResponseWriter, r *http.Request) {
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

	if !contains(sessionRoles, "edit-invites") {
		utils.RenderRedirectPage(w, "You do not have permission to send invitations", h.Config.AllInvitationsPath, 5)
		return
	}

	hostsUrl := fmt.Sprintf("%s/hosts", h.Config.Invitations)
	hosts := getStringsFromJson(hostsUrl)

	instructorsUrl := fmt.Sprintf("%s/instructors", h.Config.Invitations)
	instructors := getStringsFromJson(instructorsUrl)

	data := InvitePageData{
		Languages:          []string{"English", "Spanish", "French", "Italian", "Portuguese", "German", "Persian"},
		CSRF:               csrf.Token(r),
		CreateMessagePath:  h.Config.CreateMessagePath,
		ManagerPath:        h.Config.ManagerPath,
		AllInvitationsPath: h.Config.AllInvitationsPath,
		NewInvitationPath:  h.Config.NewInvitationPath,
		Hosts:              hosts,
		Instructors:        instructors,
		ActivityTypes: []string{"Monologue", "Dialog Format", "Interview", "Thematic Round Table", "Open Mic",
			"Open Topic Gnostic Talk", "Multi-institutional Radio Activity", "SAW Audio Translation", "Easter Special",
			"Christmas Special", "Pre-recorded Translation", "Pre-Recorded Activity", "Bilingual Activity", "Practice",
			"Pre-recorded Practice"},
		CurrentUser:         sessionUser,
		UpdatePwdPath:       h.Config.UpdatePwdPath,
		LogoutPath:          h.Config.LogoutPath,
		UserRoles:           sessionRoles,
		NewTranslationPath:  h.Config.NewTranslationPath,
		AllTranslationsPath: h.Config.AllTranslationsPath,
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
				h.handleCreate(client, w, r, &data)

			case "add_instructor":
				newInstructor := r.FormValue("new_instructor")
				if newInstructor == "" {
					data.Error = "Instructor name cannot be empty"
					break
				}

				resp, err := client.Post(
					fmt.Sprintf("%s/instructors/%s", h.Config.Invitations, url.PathEscape(newInstructor)),
					"text/plain",
					nil,
				)
				if err != nil {
					data.Error = fmt.Sprintf("Failed to add instructor: %v", err)
					log.Printf("Error adding instructor: %v", err)
				} else {
					resp.Body.Close()
					http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
					return
				}

			case "delete_instructor":
				instructor := r.FormValue("instructor_to_delete")
				if instructor == "" {
					data.Error = "No instructor selected for deletion"
					break
				}

				req, _ := http.NewRequest(
					http.MethodDelete,
					fmt.Sprintf("%s/instructors/%s", h.Config.Invitations, url.PathEscape(instructor)),
					nil,
				)
				resp, err := client.Do(req)
				if err != nil {
					data.Error = fmt.Sprintf("Failed to delete instructor: %v", err)
					log.Printf("Error deleting instructor: %v", err)
				} else {
					resp.Body.Close()
					http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
					return
				}

			case "add_host":
				newHost := r.FormValue("new_host")
				if newHost == "" {
					data.Error = "Host name cannot be empty"
					break
				}

				resp, err := client.Post(
					fmt.Sprintf("%s/hosts/%s", h.Config.Invitations, url.PathEscape(newHost)),
					"text/plain",
					nil,
				)
				if err != nil {
					data.Error = fmt.Sprintf("Failed to add host: %v", err)
					log.Printf("Error adding host: %v", err)
				} else {
					resp.Body.Close()
					http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
					return
				}

			case "delete_host":
				host := r.FormValue("host_to_delete")
				if host == "" {
					data.Error = "No host selected for deletion"
					break
				}

				req, _ := http.NewRequest(
					http.MethodDelete,
					fmt.Sprintf("%s/hosts/%s", h.Config.Invitations, url.PathEscape(host)),
					nil,
				)
				resp, err := client.Do(req)
				if err != nil {
					data.Error = fmt.Sprintf("Failed to delete host: %v", err)
					log.Printf("Error deleting host: %v", err)
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

	tmpl := template.New("create-engagement.html").Funcs(template.FuncMap{
		"contains": func(s []string, str string) bool {
			for _, v := range s {
				if v == str {
					return true
				}
			}
			return false
		},
	})

	tmpl, err = tmpl.ParseFiles("templates/create-engagement.html")
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "create-engagement.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerWithConfig) handleCreate(client *http.Client, w http.ResponseWriter, r *http.Request, data *InvitePageData) {
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

	newEng := NewEngagement{
		Instructor:    r.FormValue("instructor"),
		Host:          r.FormValue("host"),
		Date:          r.FormValue("date"),
		Language:      r.FormValue("language"),
		Title:         r.FormValue("title"),
		Part:          parseInt(r.FormValue("part")),
		NumParts:      parseInt(r.FormValue("num_parts")),
		Status:        r.FormValue("status"),
		HostStatus:    r.FormValue("host_status"),
		FlyerStatus:   r.FormValue("flyer_status"),
		Notes:         r.FormValue("notes"),
		Number:        r.FormValue("number"),
		ActivityType:  r.FormValue("activity_type"),
		LastUpdatedBy: sessionUser,
	}

	jsonData, err := json.Marshal(newEng)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating engagement request: %v", err)
		log.Printf("Error marshaling new engagement data: %v", err)
		return
	}

	url := fmt.Sprintf("%s/engs", h.Config.Invitations)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		data.Error = fmt.Sprintf("Error creating engagement request: %v", err)
		log.Printf("Error creating engagement request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating engagement: %v", err)
		log.Printf("Error creating engagement: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		data.Error = fmt.Sprintf("Failed to create engagement. Status: %d", resp.StatusCode)
		log.Printf("Create request failed with status: %d", resp.StatusCode)
	}
}

func (h *HandlerWithConfig) handleEdit(client *http.Client, w http.ResponseWriter, r *http.Request, data *InvitePageData) {
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

	editEng := Engagement{
		ID:            r.FormValue("id"),
		Instructor:    r.FormValue("instructor"),
		Host:          r.FormValue("host"),
		Date:          r.FormValue("date"),
		Language:      r.FormValue("language"),
		Title:         r.FormValue("title"),
		Part:          parseInt(r.FormValue("part")),
		NumParts:      parseInt(r.FormValue("num_parts")),
		Status:        r.FormValue("status"),
		HostStatus:    ptrFromStr(r.FormValue("host_status")),
		FlyerStatus:   ptrFromStr(r.FormValue("flyer_status")),
		Notes:         ptrFromStr(r.FormValue("notes")),
		Number:        ptrFromStr(r.FormValue("number")),
		ActivityType:  ptrFromStr(r.FormValue("activity_type")),
		LastUpdatedBy: &sessionUser,
	}

	if notes := r.FormValue("notes"); notes != "" {
		editEng.Notes = &notes
	}

	jsonData, err := json.Marshal(editEng)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating edit request: %v", err)
		log.Printf("Error marshaling edit data: %v", err)
		return
	}

	url := fmt.Sprintf("%s/engs", h.Config.Invitations)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		data.Error = fmt.Sprintf("Error creating edit request: %v", err)
		log.Printf("Error creating edit request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		data.Error = fmt.Sprintf("Error updating engagement: %v", err)
		log.Printf("Error updating engagement: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data.Error = fmt.Sprintf("Failed to update engagement. Status: %d", resp.StatusCode)
		log.Printf("Edit request failed with status: %d", resp.StatusCode)
	}
}

func (h *HandlerWithConfig) handleDelete(client *http.Client, r *http.Request, data *InvitePageData) {
	engagementID := r.FormValue("id")
	if engagementID == "" {
		data.Error = "No engagement ID provided for deletion"
		return
	}

	url := fmt.Sprintf("%s/engs/%s", h.Config.Invitations, engagementID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		data.Error = fmt.Sprintf("Error creating delete request: %v", err)
		log.Printf("Error creating delete request: %v", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		data.Error = fmt.Sprintf("Error deleting engagement: %v", err)
		log.Printf("Error deleting engagement: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data.Error = fmt.Sprintf("Failed to delete engagement. Status: %d", resp.StatusCode)
		log.Printf("Delete request failed with status: %d", resp.StatusCode)
	}
}

func createSecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func parseInt(s string) int {
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}

func ptrFromStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
