package api

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

var SetJWTAutCookie = func(httpToken string, requestOrigin string, secure bool) map[string]string {

	var headers map[string]string
	if httpToken != "" {
		token := httpToken

		// Cookie stringini hazırla
		exp := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC1123)

		var cookieStr string

		cookieStr = fmt.Sprintf(
			"authToken=%s; Expires=%s; Path=/; Domain=%s; HttpOnly; SameSite=Strict;",
			token, exp, requestOrigin,
		)

		if secure {
			cookieStr = fmt.Sprintf(
				"authToken=%s; Expires=%s; Path=/; Domain=%s; HttpOnly; Secure;  SameSite=Strict;",
				token, exp, requestOrigin,
			)
		}

		if !isOriginAllowed(requestOrigin) {
			return headers
		}

		headers = map[string]string{
			"Set-Cookie":                       cookieStr,
			"Access-Control-Allow-Origin":      requestOrigin,
			"Access-Control-Allow-Credentials": "true",
			"Content-Type":                     "application/json",
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

func isOriginAllowed(origin string) bool {

	allowedDomains := []string{"localhost", "lemoras.com"}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return false
	}

	originHost := parsedOrigin.Host

	if strings.HasPrefix(originHost, "localhost:") {
		originHost = "localhost"
	}

	for _, domain := range allowedDomains {
		if originHost == domain {
			return true
		}

		if strings.HasSuffix(originHost, "."+domain) {
			return true
		}
	}

	return false
}
