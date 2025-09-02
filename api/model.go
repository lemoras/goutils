package api

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type Response struct {
	StatusCode int               `json:"statusCode,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
}

type Context struct {
	UserId        uuid.UUID `json:"userId"`
	RoleId        int       `json:"roleId"`
	AppId         int       `json:"appId"`
	MerchantId    uuid.UUID `json:"merchantId"`
	HasId         bool      `json:"hasId"`
	ProjectId     int       `json:"projectId"`
	CustomData    string    `json:"customData"`
	InitCompleted bool      `json:"initCompleted"`
}

type Token struct {
	UserId        uuid.UUID
	RoleId        int
	AppId         int
	MerchantId    uuid.UUID
	HasId         bool
	ProjectId     int
	CustomData    string
	InitCompleted bool
	jwt.StandardClaims
}

type CustomHttp struct {
	CustomHeader CustomHeader `json:"headers"`
	Method       string       `json:"method"`
	Path         string       `json:"path"`
}

type CustomHeader struct {
	Authorization string `json:"authorization"`
	Referer       string `json:"referer"`
	Cookie        string `json:"cookie"`
	XAPIKey       string `json:"x-api-key"`
}
