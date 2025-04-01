package handler

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/harr1424/bulletinboard/pkg/config"
)

func (h *HandlerWithConfig) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.Store.Get(r, "session-name")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// check if session has expired 
		if created, ok := session.Values["created"].(int64); ok {
			if time.Since(time.Unix(created, 0)) > time.Hour * 24 {
				session.Options.MaxAge = -1
				session.Save(r, w)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}

		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		csp := []string{
			"default-src 'self'",

			"style-src 'self' https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com",

			"style-src-elem 'self' https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com",

			"script-src 'self' 'strict-dynamic' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com",

			"img-src 'self' data: https:",

			"font-src 'self' https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com",

			"media-src 'self'",
		}

		w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

func RunServer(cfg *config.Config) {
	handler, err := NewHandlerWithConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize handler: %v", err)
	}

	csrfMiddleware := csrf.Protect(
		handler.CSRFKey,
		csrf.Secure(true),
		csrf.Path("/"),
	)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			// Required for HTTP/2
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

			// Additional secure cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(handler.Config.LoginPath, handler.loginHandler)
	mux.HandleFunc(handler.Config.LogoutPath, handler.logoutHandler)
	mux.HandleFunc(handler.Config.UpdatePwdPath, handler.updateHandler)
	mux.Handle(handler.Config.SubmitMessagePath, handler.authMiddleware(http.HandlerFunc(handler.handleSubmit)))
	mux.Handle(handler.Config.CreateMessagePath, handler.authMiddleware(http.HandlerFunc(handler.renderForm)))
	mux.Handle(handler.Config.ManagerPath, handler.authMiddleware(http.HandlerFunc(handler.renderManager)))
	mux.Handle(handler.Config.NewInvitationPath, handler.authMiddleware(http.HandlerFunc(handler.renderCreateEngagement)))
	mux.Handle(handler.Config.AllInvitationsPath, handler.authMiddleware(http.HandlerFunc(handler.renderEngagementsList)))
	mux.Handle(handler.Config.NewTranslationPath, handler.authMiddleware(http.HandlerFunc(handler.renderNewTranslationPage)))
	mux.Handle(handler.Config.AllTranslationsPath, handler.authMiddleware(http.HandlerFunc(handler.renderTranslationsList)))

	secureHandler := securityHeaders(csrfMiddleware(mux))

	server := &http.Server{
		Addr:         cfg.Address,
		Handler:      secureHandler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Fatal(server.ListenAndServeTLS(cfg.CertPath, cfg.KeyPath))
}
