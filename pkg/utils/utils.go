package utils

import (
	"fmt"
	"net/http"
)

func StringPointer(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func RenderRedirectPage(w http.ResponseWriter, message, redirectURL string, delay int) {
	html := fmt.Sprintf(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Status Message</title>
            <meta http-equiv="refresh" content="%d;url=%s">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .message { font-size: 1.5em; color: #333; }
            </style>
        </head>
        <body>
            <div class="message">%s</div>
            <p>You will be redirected in %d seconds...</p>
        </body>
        </html>
    `, delay, redirectURL, message, delay)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
