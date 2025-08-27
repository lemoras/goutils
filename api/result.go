package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var (
	key, secret, bucket, region string
	ErrNoFilename               = errors.New("no filename provided")
	ErrNoRequest                = errors.New("no request type provided")
	ErrNoDuration               = errors.New("no duration provided")
	ErrNegativeDuration         = errors.New("negative duration provided")
)

func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

func ErrMessage(status bool, err error) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": err}
}

func RespondError(err error) (*Response, error) {
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{},
		Body:       "",
	}, err
}

func Respond(data map[string]interface{}) (*Response, error) {
	jsonData, _ := json.Marshal(data)
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{},
		Body:       string(jsonData),
	}, nil
}

func RespondErrorWithHeaders(err error, headers map[string]string) (*Response, error) {
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headers,
		Body:       fmt.Sprintf("Error message is ", err.Error()),
	}, err
}

func RespondWithHeaders(data map[string]interface{}, headers map[string]string) (*Response, error) {
	jsonData, _ := json.Marshal(data)
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headers,
		Body:       string(jsonData),
	}, nil
}

func RespondNoContent() (*Response, error) {
	return &Response{
		StatusCode: http.StatusNoContent,
		Headers:    map[string]string{},
		Body:       "",
	}, nil
}

func ResMessage(status bool, message string) (bool, Response) {
	jsonData, _ := json.Marshal(Message(status, message))
	return status, Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{},
		Body:       string(jsonData),
	}
}

func CheckOk(data map[string]interface{}) bool {
	return data["status"].(bool)
}

const (
	None = iota
	Root
	MerchantAdmin
	Admin
	Superuser
	User
	Member
)
