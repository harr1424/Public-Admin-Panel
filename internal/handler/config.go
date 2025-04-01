package handler

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/harr1424/bulletinboard/pkg/config"
	"golang.org/x/time/rate"
)

type HandlerWithConfig struct {
	Config      *config.Config
	Store       *sessions.CookieStore
	RateLimiter *IPRateLimiter
	CSRFKey     []byte
}

var (
	sessionKeys struct {
		authKey []byte
		encKey  []byte
		once    sync.Once
	}
)

func initSessionKeys() error {
	var err error
	sessionKeys.once.Do(func() {
		sessionKeys.authKey = securecookie.GenerateRandomKey(32)
		sessionKeys.encKey = securecookie.GenerateRandomKey(32)

		if sessionKeys.authKey == nil || sessionKeys.encKey == nil {
			err = fmt.Errorf("failed to generate session keys")
			return
		}
	})
	return err
}

func NewHandlerWithConfig(cfg *config.Config) (*HandlerWithConfig, error) {
	if err := initSessionKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize session keys: %v", err)
	}

	store := &sessions.CookieStore{
		Codecs: []securecookie.Codec{
			securecookie.New(sessionKeys.authKey, sessionKeys.encKey),
		},
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   60 * 60 * 24,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		},
	}

	csrfKey := securecookie.GenerateRandomKey(32)
	if csrfKey == nil {
		return nil, fmt.Errorf("failed to generate CSRF key")
	}

	rateLimiter := NewIPRateLimiter(rate.Every(10*time.Second), 6)

	return &HandlerWithConfig{
		Config:      cfg,
		Store:       store,
		RateLimiter: rateLimiter,
		CSRFKey:     csrfKey,
	}, nil
}
