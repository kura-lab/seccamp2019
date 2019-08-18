package main

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
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

const CLIENT_ID = "<CLIENT_ID>"
const CLIENT_SECRET = "<CLIENT_SECRET>"
const REDIRECT_URI = "http://localhost:8080/callback"

func index(writer http.ResponseWriter, request *http.Request) {
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
	u.RawQuery = q.Encode()
	d := DataIndex{AuthorizationUrl: u.String()}
	renderTemplate(writer, d, "index")
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

type UserInfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

func callback(writer http.ResponseWriter, request *http.Request) {
	// request token endpoint
	query := request.URL.Query()
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Add("client_id", CLIENT_ID)
	values.Add("client_secret", CLIENT_SECRET)
	values.Add("redirect_uri", REDIRECT_URI)
	values.Add("code", query["code"][0])
	req, err := http.NewRequest(
		"POST",
		"https://auth.login.yahoo.co.jp/yconnect/v2/token",
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
		return
	}

	data := new(TokenResponse)
	err = json.Unmarshal(body, data)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
		return
	}

	// request userinfo endpoint
	req2, err := http.NewRequest(
		"POST",
		"https://userinfo.yahooapis.jp/yconnect/v2/attribute",
		nil,
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
		return
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+data.AccessToken)
	client2 := &http.Client{}
	resp2, err := client2.Do(req2)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
		return
	}
	defer resp2.Body.Close()

	body2, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
		return
	}

	data2 := new(UserInfoResponse)
	err = json.Unmarshal(body2, data2)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
		return
	}

	renderTemplate(writer, data2, "callback")
}

func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
	templates := template.Must(template.ParseFiles("templates/" + filename + ".html"))
	templates.ExecuteTemplate(writer, filename, data)
}
