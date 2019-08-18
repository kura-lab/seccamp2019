package main

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/callback", callback)
	mux.HandleFunc("/authentication", authentication)

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
const REDIRECT_URI = "http://localhost:8080/callback"

func index(writer http.ResponseWriter, request *http.Request) {
	// generate authorization endpoint url
	endpoint := "https://auth.login.yahoo.co.jp"
	u, err := url.Parse(endpoint)
	if err != nil {
		e := Error{Error: "url parse error"}
		renderTemplate(writer, e, "error")
	}
	u.Path = path.Join(u.Path, "yconnect/v2/authorization")
	q := u.Query()
	q.Set("response_type", "token")
	q.Set("client_id", CLIENT_ID)
	q.Set("redirect_uri", REDIRECT_URI)
	q.Set("scope", "openid email")
	u.RawQuery = q.Encode()
	d := DataIndex{AuthorizationUrl: u.String()}
	renderTemplate(writer, d, "index")
}

func callback(writer http.ResponseWriter, request *http.Request) {
	renderTemplate(writer, nil, "callback")
}

type UserInfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

func authentication(writer http.ResponseWriter, request *http.Request) {
	// request userinfo endpoint
	query := request.URL.Query()
	req, err := http.NewRequest(
		"POST",
		"https://userinfo.yahooapis.jp/yconnect/v2/attribute",
		nil,
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+query["access_token"][0])
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
	}

	data := new(UserInfoResponse)
	err = json.Unmarshal(body, data)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
	}

	renderTemplate(writer, data, "authentication")
}

func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
	templates := template.Must(template.ParseFiles("templates/" + filename + ".html"))
	templates.ExecuteTemplate(writer, filename, data)
}
