package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/index", index)
	mux.HandleFunc("/callback", callback)

	server := &http.Server{
		Addr:           "0.0.0.0:8080",
		Handler:        mux,
		ReadTimeout:    time.Duration(10 * int64(time.Second)),
		WriteTimeout:   time.Duration(600 * int64(time.Second)),
		MaxHeaderBytes: 1 << 20,
	}
	server.ListenAndServe()
}

type DataIndex struct {
	AuthorizationUrl string
}

type Error struct {
	Error string
}

var randLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func generateRandomString() string {
	rand.Seed(time.Now().UnixNano())
	result := make([]rune, 32)
	for i := range result {
		result[i] = randLetters[rand.Intn(len(randLetters))]
	}
	return string(result)
}

const CLIENT_ID = "<CLIENT_ID>"
const CLIENT_SECRET = "<CLIENT_SECRET>"
const REDIRECT_URI = "http://localhost:8080/callback"

func index(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("[[ login started ]]")
	// store state and nonce in session
	state := generateRandomString()
	stateCookie := &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(writer, stateCookie)

	// generate authorization endpoint url
	authorizationEndpoint := "https://auth.login.yahoo.co.jp"
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		e := Error{Error: "url parse error"}
		renderTemplate(writer, e, "error")
		return
	}
	u.Path = path.Join(u.Path, "yconnect/v2/authorization")
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", CLIENT_ID)
	q.Set("redirect_uri", REDIRECT_URI)
	q.Set("scope", "openid email")
	q.Set("state", state)
	u.RawQuery = q.Encode()
	fmt.Println("generated authorization endpoint url")
	indexData := DataIndex{AuthorizationUrl: u.String()}
	renderTemplate(writer, indexData, "index")
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

type UserInfoResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

func callback(writer http.ResponseWriter, request *http.Request) {
	// verify state
	query := request.URL.Query()
	state := query["state"][0]
	storedState, err := request.Cookie("state")
	if err != nil {
		e := Error{Error: "state cookie error"}
		renderTemplate(writer, e, "error")
		return
	}
	if state != storedState.Value {
		e := Error{Error: "state does not match stored one"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify state")

	// request token endpoint
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Add("client_id", CLIENT_ID)
	values.Add("client_secret", CLIENT_SECRET)
	values.Add("redirect_uri", REDIRECT_URI)
	values.Add("code", query["code"][0])
	tokenRequest, err := http.NewRequest(
		"POST",
		"https://auth.login.yahoo.co.jp/yconnect/v2/token",
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
		return
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenClient := &http.Client{}
	tokenResponse, err := tokenClient.Do(tokenRequest)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
		return
	}
	defer tokenResponse.Body.Close()

	tokenBody, err := ioutil.ReadAll(tokenResponse.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
		return
	}

	tokenData := new(TokenResponse)
	err = json.Unmarshal(tokenBody, tokenData)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("requested token endpoint")

	// verify id token header

	// verify typ

	// verify alg

	// request jwts endpoint

	// extract modulus and exponent

	// generate public key from n(modulus) and e(exponent)

	// verifiy id token signature

	// verify id token claims

	// verify issuer

	// verify audience

	// verify nonce

	// verify iat

	// verify at_hash

	// whether you use the following or not is up to you
	// - idTokenPayload.Expiration
	// - idTokenPayload.AuthTime
	// - idTokenPayload.AuthenticationMethodReference

	// request userinfo endpoint
	userInfoRequest, err := http.NewRequest(
		"POST",
		"https://userinfo.yahooapis.jp/yconnect/v2/attribute",
		nil,
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
		return
	}
	userInfoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	userInfoRequest.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	client2 := &http.Client{}
	userInfoResponse, err := client2.Do(userInfoRequest)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
		return
	}
	defer userInfoResponse.Body.Close()

	userInfoBody, err := ioutil.ReadAll(userInfoResponse.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
		return
	}

	userInfoData := new(UserInfoResponse)
	err = json.Unmarshal(userInfoBody, userInfoData)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("requested userinfo endpoint")

	// verify user id

	renderTemplate(writer, userInfoData, "callback")
	fmt.Println("[[ login completed ]]")
}

func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
	templates := template.Must(template.ParseFiles("templates/" + filename + ".html"))
	templates.ExecuteTemplate(writer, filename, data)
}
