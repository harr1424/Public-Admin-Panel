package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

type User struct {
	Name     string
	Password string
}

type Config struct {
	Address             string
	CreateMessagePath   string
	SubmitMessagePath   string
	LoginPath           string
	ManagerPath         string
	ApiKey              string
	RemoteServer        string
	RemoteGet           string
	CertPath            string
	KeyPath             string
	Invitations         string
	AllInvitationsPath  string
	NewInvitationPath   string
	AuthPath            string
	UpdatePwdPath       string
	LogoutPath          string
	AllTranslationsPath string
	NewTranslationPath  string
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, errors.New("could not load .env file")
	}

	address := os.Getenv("redacted")
	createMessagePath := os.Getenv("redacted")
	sendMessagePath := os.Getenv("redacted")
	loginPath := os.Getenv("redacted")
	managerPath := os.Getenv("redacted")
	apiKey := os.Getenv("redacted")
	remoteServer := os.Getenv("redacted")
	remoteGet := os.Getenv("redacted")
	certPath := os.Getenv("redacted")
	keyPath := os.Getenv("redacted")
	invitations := os.Getenv("redacted")
	allInvitationsPath := os.Getenv("redacted")
	newInvitationPath := os.Getenv("redacted")
	authPath := os.Getenv("redacted")
	updatePwdPath := os.Getenv("redacted")
	logoutPath := os.Getenv("redacted")
	allTranslationsPath := os.Getenv("redacted")
	newTranslationPath := os.Getenv("redacted")

	if address == "" ||
		createMessagePath == "" ||
		sendMessagePath == "" ||
		loginPath == "" ||
		managerPath == "" ||
		apiKey == "" ||
		remoteServer == "" ||
		remoteGet == "" ||
		certPath == "" ||
		keyPath == "" ||
		invitations == "" ||
		allInvitationsPath == "" ||
		newInvitationPath == "" ||
		authPath == "" ||
		updatePwdPath == "" ||
		logoutPath == "" ||
		allTranslationsPath == "" ||
		newTranslationPath == "" {
		return nil, errors.New("missing required environment variables")
	}

	return &Config{
		Address:             address,
		CreateMessagePath:   createMessagePath,
		SubmitMessagePath:   sendMessagePath,
		LoginPath:           loginPath,
		ManagerPath:         managerPath,
		ApiKey:              apiKey,
		RemoteServer:        remoteServer,
		RemoteGet:           remoteGet,
		CertPath:            certPath,
		KeyPath:             keyPath,
		Invitations:         invitations,
		AllInvitationsPath:  allInvitationsPath,
		NewInvitationPath:   newInvitationPath,
		AuthPath:            authPath,
		UpdatePwdPath:       updatePwdPath,
		LogoutPath:          logoutPath,
		AllTranslationsPath: allTranslationsPath,
		NewTranslationPath:  newTranslationPath,
	}, nil
}
