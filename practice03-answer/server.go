package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/big"
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
	nonce := generateRandomString()
	nonceCookie := &http.Cookie{
		Name:     "nonce",
		Value:    nonce,
		HttpOnly: true,
	}
	http.SetCookie(writer, nonceCookie)
	fmt.Println("stored state and nonce in session")

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
	q.Set("nonce", nonce)
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

type IdTokenHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyId     string `json:"kid"`
}

type IdTokenPayload struct {
	Issuer                        string   `json:"iss"`
	Subject                       string   `json:"sub"`
	Audience                      []string `json:"aud"`
	Expiration                    int      `json:"exp"`
	IssueAt                       int      `json:"iat"`
	AuthTime                      int      `json:"auth_time"`
	Nonce                         string   `json:"nonce"`
	AuthenticationMethodReference []string `json:"amr"`
	AccessTokenHash               string   `json:"at_hash"`
}

type JwksResponse struct {
	KeySets []struct {
		KeyId     string `json:"kid"`
		KeyType   string `json:"kty"`
		Algorithm string `json:"alg"`
		Use       string `json:"use"`
		Modulus   string `json:"n"`
		Exponent  string `json:"e"`
	} `json:"keys"`
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
	stateCookie := &http.Cookie{
		Name:   "state",
		MaxAge: -1,
	}
	http.SetCookie(writer, stateCookie)

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
	idTokenParts := strings.Split(tokenData.IdToken, ".")
	fmt.Println("header: ", idTokenParts[0])
	fmt.Println("payload: ", idTokenParts[1])
	fmt.Println("signature: ", idTokenParts[2])

	header, _ := base64.RawURLEncoding.DecodeString(idTokenParts[0])
	idTokenHeader := new(IdTokenHeader)
	_ = json.Unmarshal(header, idTokenHeader)
	fmt.Println("typ: ", idTokenHeader.Type)
	fmt.Println("alg: ", idTokenHeader.Algorithm)

	// verify typ
	if idTokenHeader.Type != "JWT" {
		e := Error{Error: "invalid id token type"}
		renderTemplate(writer, e, "error")
		return
	}
	// verify alg
	if idTokenHeader.Algorithm != "RS256" {
		e := Error{Error: "invalid id token algorithm"}
		renderTemplate(writer, e, "error")
		return
	}

	// request jwts endpoint
	jwksRequest, err := http.NewRequest(
		"GET",
		"https://auth.login.yahoo.co.jp/yconnect/v2/jwks",
		nil,
	)
	if err != nil {
		e := Error{Error: "new http request error"}
		renderTemplate(writer, e, "error")
		return
	}
	jwksClient := &http.Client{}
	jwksResponse, err := jwksClient.Do(jwksRequest)
	if err != nil {
		e := Error{Error: "post request error"}
		renderTemplate(writer, e, "error")
		return
	}
	defer jwksResponse.Body.Close()

	jwksBody, err := ioutil.ReadAll(jwksResponse.Body)
	if err != nil {
		e := Error{Error: "read body error"}
		renderTemplate(writer, e, "error")
		return
	}

	jwksData := new(JwksResponse)
	err = json.Unmarshal(jwksBody, jwksData)
	if err != nil {
		e := Error{Error: "json parse error"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("requested jwks endpoint")

	// extract modulus and exponent
	modulus := ""
	exponent := ""
	for _, keySet := range jwksData.KeySets {
		if keySet.KeyId == idTokenHeader.KeyId {
			fmt.Println("kid: " + keySet.KeyId)
			if keySet.KeyType != "RSA" || keySet.Algorithm != idTokenHeader.Algorithm || keySet.Use != "sig" {
				e := Error{Error: "invalid kid, alg or use"}
				renderTemplate(writer, e, "error")
				return
			}
			modulus = keySet.Modulus
			exponent = keySet.Exponent
			break
		}
	}
	fmt.Println("modulus: ", modulus)
	fmt.Println("exponent: ", exponent)

	if modulus == "" || exponent == "" {
		e := Error{Error: "failed to extract modulus or exponent"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("extracted modulus and exponent")

	// generate public key from n(modulus) and e(exponent)
	decodedModulus, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		e := Error{Error: "failed to decode modulus"}
		renderTemplate(writer, e, "error")
		return
	}
	n := big.NewInt(0)
	n.SetBytes(decodedModulus)

	decodedExponent, err := base64.StdEncoding.DecodeString(exponent)
	if err != nil {
		e := Error{Error: "failed to decode exponent"}
		renderTemplate(writer, e, "error")
		return
	}
	var exponentBytes []byte
	if len(decodedExponent) < 8 {
		exponentBytes = make([]byte, 8-len(decodedExponent), 8)
		exponentBytes = append(exponentBytes, decodedExponent...)
	} else {
		exponentBytes = decodedExponent
	}
	reader := bytes.NewReader(exponentBytes)
	var e uint64
	err = binary.Read(reader, binary.BigEndian, &e)
	if err != nil {
		e := Error{Error: "failed to read binary exponent"}
		renderTemplate(writer, e, "error")
		return
	}
	generatedPublicKey := rsa.PublicKey{N: n, E: int(e)}
	fmt.Println("generated public key: ", generatedPublicKey)
	fmt.Println("generated public key from n and e")

	// verifiy id token signature
	decodedSignature, err := base64.RawURLEncoding.DecodeString(idTokenParts[2])
	if err != nil {
		e := Error{Error: "failed to decode signature"}
		renderTemplate(writer, e, "error")
		return
	}

	hash := crypto.Hash.New(crypto.SHA256)
	hash.Write([]byte(idTokenParts[0] + "." + idTokenParts[1]))
	hashed := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(&generatedPublicKey, crypto.SHA256, hashed, decodedSignature)
	if err != nil {
		fmt.Println("failed to verify signature")
		return
	}
	fmt.Println("success to verify signature")

	// verify id token claims
	decodedPayload, err := base64.RawURLEncoding.DecodeString(idTokenParts[1])
	if err != nil {
		e := Error{Error: "failed to decode payload"}
		renderTemplate(writer, e, "error")
		return
	}

	idTokenPayload := new(IdTokenPayload)
	err = json.Unmarshal(decodedPayload, idTokenPayload)
	if err != nil {
		e := Error{Error: "payload json parse error"}
		renderTemplate(writer, e, "error")
		return
	}

	// verify issuer
	fmt.Println("id token issuer: ", idTokenPayload.Issuer)
	if idTokenPayload.Issuer != "https://auth.login.yahoo.co.jp/yconnect/v2" {
		e := Error{Error: "mismatched issuer"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify issuer")

	// verify audience
	fmt.Println("id token audience: ", idTokenPayload.Audience)
	resultAudience := false
	for _, audience := range idTokenPayload.Audience {
		if audience == CLIENT_ID {
			fmt.Println("mached audience: ", audience)
			resultAudience = true
			break
		}
	}

	if resultAudience != true {
		e := Error{Error: "mismatched audience"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify audience")

	// verify nonce
	storedNonce, err := request.Cookie("nonce")
	if err != nil {
		e := Error{Error: "nonce cookie error"}
		renderTemplate(writer, e, "error")
		return
	}
	nonceCookie := &http.Cookie{
		Name:   "nonce",
		MaxAge: -1,
	}
	http.SetCookie(writer, nonceCookie)
	fmt.Println("id token nonce: ", idTokenPayload.Nonce)
	fmt.Println("stored nonce: ", storedNonce.Value)

	if idTokenPayload.Nonce != storedNonce.Value {
		e := Error{Error: "nonce does not match stored one"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify nonce")

	// verify iat
	fmt.Println("id token iat: ", idTokenPayload.IssueAt)
	if int(time.Now().Unix())-idTokenPayload.IssueAt >= 600 {
		e := Error{Error: "too far away from current time"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify issue at")

	// verify at_hash
	receivedAccessTokenHash := sha256.Sum256([]byte(tokenData.AccessToken))
	halfOfAccessTokenHash := receivedAccessTokenHash[:len(receivedAccessTokenHash)/2]
	encodedhalfOfAccessTokenHash := base64.RawURLEncoding.EncodeToString(halfOfAccessTokenHash)
	fmt.Println("id token at_hash: ", idTokenPayload.AccessTokenHash)
	fmt.Println("generated at_hash: ", encodedhalfOfAccessTokenHash)
	if idTokenPayload.AccessTokenHash != encodedhalfOfAccessTokenHash {
		e := Error{Error: "mismatched at_hash"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify at_hash")

	// whether you use the following or not is up to you
	// - idTokenPayload.Expiration
	// - idTokenPayload.AuthTime
	// - idTokenPayload.AuthenticationMethodReference

	fmt.Println("success to verify id token claims")

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
	fmt.Println("id token sub: ", idTokenPayload.Subject)
	fmt.Println("userinfo sub: ", userInfoData.Subject)
	if idTokenPayload.Subject != userInfoData.Subject {
		e := Error{Error: "mismatched user id"}
		renderTemplate(writer, e, "error")
		return
	}
	fmt.Println("success to verify user id")

	renderTemplate(writer, userInfoData, "callback")
	fmt.Println("[[ login completed ]]")
}

func renderTemplate(writer http.ResponseWriter, data interface{}, filename string) {
	templates := template.Must(template.ParseFiles("templates/" + filename + ".html"))
	templates.ExecuteTemplate(writer, filename, data)
}
