package api

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var JwtAuthentication = func(requestToken string, context *Context) (bool, Response) {

	result := Response{}

	ips, err := GetLocalIPs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ips)

	if requestToken == "" { //Token is missing, returns with error code 403 Unauthorized
		return ResMessage(false, "0x11130:Missing auth token")
	}

	splitted := strings.Split(requestToken, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
	if len(splitted) != 2 {
		return ResMessage(false, "0x11143:Invalid/Malformed auth token")
	}

	tokenPart := splitted[1] //Grab the token part, what we are truly interested in
	tk := &Token{}

	token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("token_secret_key")), nil
	})

	if err != nil { //Malformed token, returns with http code 403 as usual

		token, err = jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_root_secret_key")), nil
		})

		if err != nil {
			return ResMessage(false, "0x11144:Malformed authentication token")
		}
	}

	if !token.Valid { //Token is invalid, maybe not signed on this server
		return ResMessage(false, "Token is not valid.")
	}

	context.UserId = tk.UserId
	context.RoleId = tk.RoleId
	context.AppId = tk.AppId
	context.MerchantId = tk.MerchantId
	context.HasId = tk.HasId
	context.ProjectId = tk.ProjectId
	context.CustomData = tk.CustomData
	context.InitCompleted = tk.InitCompleted

	return true, result
}
