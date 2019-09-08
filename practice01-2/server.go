package main

import (
	"html/template"
	"net/http"
	"net/url"
	"path"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/index", index)
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

type DataAuthentication struct {
	Sub   string
	Email string
}

func authentication(writer http.ResponseWriter, request *http.Request) {
	// receive sub and email
	request.ParseForm()
	sub := request.Form.Get("sub")
	email := request.Form.Get("email")
	data := DataAuthentication{Sub: sub, Email: email}
	renderTemplate(writer, data, "authentication")
}

func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
	templates := template.Must(template.ParseFiles("templates/" + filename + ".html"))
	templates.ExecuteTemplate(writer, filename, data)
}
