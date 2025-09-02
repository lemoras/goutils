package api

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var SetJWTAutCookie = func(httpToken string, context *Context) map[string]string {

	var headers map[string]string
	if httpToken != "" {
		token := httpToken

		// Cookie stringini hazırla
		exp := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC1123)
		cookie := fmt.Sprintf(
			"authToken=%s; Expires=%s; Path=/; Domain=.lemoras.com HttpOnly; SameSite=Strict",
			// "authToken=%s; Expires=%s; Path=/; Domain=.lemoras.com HttpOnly; Secure; SameSite=Strict",
			token, exp,
		)

		headers = map[string]string{
			"Set-Cookie":   cookie,
			"Content-Type": "application/json",
		}
	}

	return headers
}

var CheckJWTAutCookie = func(requestToken string, context *Context, headers CustomHeader) (bool, Response) {

	if headers.XAPIKey == os.Getenv("x_api_key") {
		return JwtAuthentication(requestToken, context)
	}

	tokenValue := ""
	cookies := strings.Split(headers.Cookie, "; ")
	for _, cookie := range cookies {
		parts := strings.Split(cookie, "=")
		if len(parts) == 2 && parts[0] == "authToken" {
			tokenValue = parts[1]
			break
		}
	}

	if tokenValue == "" {
		return ResMessage(false, "0x11130:Missing auth token")
	}

	return JwtAuthentication(tokenValue, context)
}

var CheckAuthEmpty = func(headers CustomHeader) bool {

	if headers.XAPIKey == os.Getenv("x_api_key") {
		return headers.Authorization == ""
	}

	if headers.Cookie == "" {
		return true
	}

	tokenValue := ""
	cookies := strings.Split(headers.Cookie, "; ")
	for _, cookie := range cookies {
		parts := strings.Split(cookie, "=")
		if len(parts) == 2 && parts[0] == "authToken" {
			tokenValue = parts[1]
			break
		}
	}

	return tokenValue == ""
}
