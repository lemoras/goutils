package api

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

var SetJWTAutCookie = func(httpToken string, requestOrigin string, hasDomain bool) map[string]string {

	var headers map[string]string
	if httpToken != "" {
		token := httpToken

		// Cookie stringini hazırla
		exp := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC1123)

		var cookieStr string

		cookieStr = fmt.Sprintf(
			"authToken=Bearer %s; Expires=%s; Path=/; HttpOnly; Secure; SameSite=None;",
			token, exp,
		)

		if hasDomain {
			cookieStr = fmt.Sprintf(
				"authToken=%s; Expires=%s; Path=/; Domain=%s; HttpOnly; Secure; SameSite=None;",
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

	if headers.XAPIKey == os.Getenv("X_API_KEY") {
		return JwtAuthentication(requestToken, context)
	}

	if headers.Cookie == "" {
		return ResMessage(false, "Missing Cookie")
	}

	cookies := strings.Split(headers.Cookie, "; ")

	var authTokenValue string

	for _, cookie := range cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 && parts[0] == "authToken" {
			authTokenValue = parts[1]
			break
		}
	}

	if authTokenValue == "" {
		return ResMessage(false, "0x11130:Missing auth token")
	}

	return JwtAuthentication(authTokenValue, context)
}

var CheckAuthEmpty = func(headers CustomHeader) bool {

	if headers.XAPIKey == os.Getenv("X_API_KEY") {
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

	allowedDomainsStr := os.Getenv("cookie_allowed_domains")

	allowedDomains := strings.Split(allowedDomainsStr, ",")

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return false
	}

	originHost := parsedOrigin.Host

	mainDomain := os.Getenv("MAIN_DOMAIN")
	if strings.HasPrefix(originHost, mainDomain+":") {
		originHost = mainDomain
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
