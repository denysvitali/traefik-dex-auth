package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"github.com/alexflint/go-arg"
	"github.com/dchest/uniuri"
	"github.com/denysvitali/traefik-dex-auth/pkg"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var rcfg *pkg.RuntimeConfig

const BASE_PATH = "/traefik-dex-auth"
const REDIRECT_URI = "redirect_uri"
const REDIRECT_HOSTNAME = "redirect_hostname"
const REDIRECT_PROTO = "redirect_proto"
const GENERIC_ERROR = "internal server error"

func main() {
	var args struct {
		ClientID     string `arg:"env:CLIENT_ID" default:"traefik-dex-auth" help:"Client ID used to identify this service with Dex"`
		ClientSecret string `arg:"env:CLIENT_SECRET" help:"Client Secret set in the Dex config"`
		DexUrl       string `arg:"env:DEX_URL" help:"Base URL of your Dex instance (e.g: http://127.0.0.1:5556)"`
		TDAUrl       string `arg:"env:TDA_URL" help:"Url of the Traefik Dex Auth instance (e.g: https://auth.example.com)"`
		CookieDomain string `arg:"env:COOKIE_DOMAIN" help:"Domain of application for the authentication cookie (e.g: example.com)"`
		HMACKey      string `arg:"env:HMAC_KEY" help:"HMAC Key, used to authenticate redirection cookies"`
		SessionKey   string `arg:"env:SESSION_KEY" help:"Session Key, used to authenticate sessions"`
		LoggingLevel string `arg:"env:LOG_LEVEL" help:"Logging level (debug, info, warning, error, fatal)"`
	}
	arg.MustParse(&args)

	log := logrus.New()
	lowercaseLL := strings.ToLower(args.LoggingLevel)

	if lowercaseLL == "debug" {
		log.SetLevel(logrus.DebugLevel)
	} else if lowercaseLL == "info" {
		log.SetLevel(logrus.InfoLevel)
	} else if lowercaseLL == "warning" {
		log.SetLevel(logrus.WarnLevel)
	} else if lowercaseLL == "error" {
		log.SetLevel(logrus.ErrorLevel)
	} else if lowercaseLL == "fatal" {
		log.SetLevel(logrus.FatalLevel)
	}

	dexUrl, err := url.Parse(args.DexUrl)
	if err != nil {
		log.Fatalf("invalid Dex url: %s", err)
	}

	tdaUrl, err := url.Parse(args.TDAUrl)
	if err != nil {
		log.Fatalf("invalid TDA url: %s", err)
	}

	if args.CookieDomain == "" {
		log.Fatalf("Cookie Domain must be specified")
	}

	if args.ClientID == "" {
		log.Fatalf("A Client ID must be provided")
	}

	if args.ClientSecret == "" {
		log.Fatalf("A Client Secret must be provided")
	}

	var hmacKey []byte
	if args.HMACKey == "" {
		hmacKey, err = ioutil.ReadAll(strings.NewReader(args.HMACKey))
		if err != nil {
			log.Fatalf("invalid HMAC Key!")
		}
	}

	if len(hmacKey) == 0 {
		hmacKey, err = ioutil.ReadAll(io.LimitReader(rand.Reader, 128))
		if err != nil {
			log.Fatalf("unable to generate HMAC key")
		}
	}
	log.Debugf("hmacKey=%v", hmacKey)

	var sessionKey []byte
	if args.SessionKey == "" {
		sessionKey, err = ioutil.ReadAll(strings.NewReader(args.SessionKey))
		if err != nil {
			log.Fatalf("invalid Session Key!")
		}
	}

	if len(sessionKey) == 0 {
		sessionKey, err = ioutil.ReadAll(io.LimitReader(rand.Reader, 128))
		if err != nil {
			log.Fatalf("unable to generate Session key")
		}
	}
	log.Debugf("sessionKey=%v", sessionKey)
	TdaCallbackUrl, err := rcfg.TdaUrl.Parse(BASE_PATH + "/callback")

	if err != nil {
		logrus.Fatalf("unable to parse callback url: %v", err)
	}

	rcfg = &pkg.RuntimeConfig{
		Logger:         log,
		DexUrl:         dexUrl,
		TdaUrl:         tdaUrl,
		HmacKey:        hmacKey,
		SessionKey:     sessionKey,
		ClientId:       args.ClientID,
		ClientSecret:   args.ClientSecret,
		TdaCallbackUrl: TdaCallbackUrl,
	}

	r := gin.Default()
	r.GET(BASE_PATH+"/login", handleLogin)
	r.GET(BASE_PATH+"/callback", handleCallback)
	r.Any("/", handleAny)

	err = r.Run()
	if err != nil {
		logrus.Fatal(err)
	}
}

func handleLogin(context *gin.Context) {
	cookie, err := context.Cookie("tda-auth")
	if err == nil {
		// Cookie set, let's check whether it's valid or not
		rcfg.Logger.Debugf("Cookie content=%v", cookie)
		rcfg.Logger.Debugf("valid cookie found, returning 200")
		context.String(http.StatusOK, "success")
		return
	}

	dexAuth, err := rcfg.DexUrl.Parse("/auth")
	if err != nil {
		rcfg.Logger.Errorf("unable to parse DEX url: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}
	dexAuth.Query().Add("response_type", "code")
	dexAuth.Query().Add("client_id", rcfg.ClientId)

	// Generate sessionNonce and sessionState to avoid replay attacks
	sessionNonce := uniuri.NewLen(25)
	sessionState := uniuri.NewLen(25)

	dexValues := dexAuth.Query()
	dexValues.Add("scope", "openid profile email")
	dexValues.Add("response_type", "code")
	dexValues.Add("client_id", rcfg.ClientId)
	dexValues.Add("redirect_uri", rcfg.TdaCallbackUrl.String())
	dexValues.Add("state", sessionState) // CSRF,XSRF mitigation
	dexValues.Add("nonce", sessionNonce) // replay attacks mitigation

	dexAuth.RawQuery = dexValues.Encode()

	type Options struct {
		Hostname  string `url:"hostname"`
		Proto     string `url:"proto"`
		Uri       string `url:"uri"`
		Timestamp int64  `url:"ts"`
	}

	originalQuery := context.Request.URL.Query()
	opt := Options{
		originalQuery.Get(REDIRECT_HOSTNAME),
		originalQuery.Get(REDIRECT_PROTO),
		originalQuery.Get(REDIRECT_URI),
		time.Now().Unix(),
	}
	v, _ := query.Values(opt)
	encodedQuery := v.Encode()
	encodedQueryBytes, err := ioutil.ReadAll(strings.NewReader(encodedQuery))

	if err != nil {
		rcfg.Logger.Errorf("unable to get bytes from string for encodedQuery")
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	mac := hmac.New(sha512.New, rcfg.HmacKey)
	mac.Reset()
	mac.Write(encodedQueryBytes)
	macBytes := mac.Sum(nil)

	macString := base64.StdEncoding.EncodeToString(macBytes)
	encodedQueryB64 := base64.StdEncoding.EncodeToString(encodedQueryBytes)

	// Authenticated string
	finalAuthString := encodedQueryB64 + "|" + macString

	context.SetCookie("tda-auth-info", finalAuthString, 60, "", "", true, true)
	context.SetCookie("tda-auth-nonce", sessionNonce, 60, "", "", true, true)
	context.SetCookie("tda-auth-state", sessionState, 60, "", "", true, true)
	context.Redirect(http.StatusTemporaryRedirect, dexAuth.String())
}

func handleCallback(context *gin.Context) {
	code := context.Query("code")
	state := context.Query("state")
	sessionState, err := context.Cookie("tda-auth-state")
	if err != nil {
		rcfg.Logger.Errorf("tda-auth-state cookie missing: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}
	sessionNonce, err := context.Cookie("tda-auth-nonce")
	if err != nil {
		rcfg.Logger.Errorf("tda-auth-nonce cookie missing: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	if code == "" {
		context.String(http.StatusBadRequest, "code missing")
		return
	}

	if state == "" {
		context.String(http.StatusBadRequest, "state missing")
		return
	}

	if sessionState != state {
		context.String(http.StatusForbidden, "invalid state")
		return
	}

	// Get Token Endpoint
	openIdConfigUrl, err := rcfg.DexUrl.Parse("/.well-known/openid-configuration")
	if err != nil {
		rcfg.Logger.Errorf("unable to determine openid-configuration URL: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	resp, err := http.Get(openIdConfigUrl.String())
	if err != nil {
		rcfg.Logger.Errorf("unable to get openId Config: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	var openIdConfig pkg.OpenIDConfiguration
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		rcfg.Logger.Errorf("unable to read openid config request body: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}
	err = json.Unmarshal(bodyBytes, &openIdConfig)
	if err != nil {
		rcfg.Logger.Errorf("unable to unmarshal json: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	if openIdConfig.TokenEndpoint == "" {
		rcfg.Logger.Errorf("Oauth 2.0 Token endpoint missing: %s")
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("redirect_uri", rcfg.TdaCallbackUrl.String())
	values.Add("client_id", rcfg.ClientId)
	encodedData := values.Encode()

	req, _ := http.NewRequest("POST",
		openIdConfig.TokenEndpoint,
		strings.NewReader(encodedData),
	)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encodedData)))

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		rcfg.Logger.Errorf("unable to perform /token request: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		rcfg.Logger.Errorf("unable to read body bytes: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	if resp.StatusCode == 400 {
		var oauthErr pkg.Oauth2TokenErrorResponse
		err = json.Unmarshal(bodyBytes, &oauthErr)
		rcfg.Logger.Errorf("token retrieval failed: %v", oauthErr)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	if resp.StatusCode != 200 {
		rcfg.Logger.Errorf("invalid status code %d", resp.StatusCode)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	var oauth2TokenResponse pkg.OpenIDTokenResponse
	err = json.Unmarshal(bodyBytes, &oauth2TokenResponse)
	if err != nil {
		rcfg.Logger.Errorf("unable to unmarshal oauth2 token response: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	token, err := jwt.Parse(oauth2TokenResponse.IdToken, pkg.ParseOpenIdToken(openIdConfig, rcfg, sessionNonce))

	if err != nil {
		rcfg.Logger.Errorf("unable to decode token: %v", err)
		context.String(http.StatusInternalServerError, GENERIC_ERROR)
		return
	}

	if !token.Valid {
		rcfg.Logger.Error("invalid token")
		context.String(http.StatusForbidden, "invalid token")
		return
	}

	context.SetCookie("tda-auth", oauth2TokenResponse.IdToken,
		oauth2TokenResponse.ExpiresIn,
		"/",
		rcfg.cookieDomain, true, true)

}

func handleAny(context *gin.Context) {
	rcfg.Logger.Debugf("Handling \"ANY\":")
	rcfg.Logger.Debugf("\tHeaders: %v", context.Request.Header)

	encodedUrl, err := rcfg.TdaUrl.Parse(BASE_PATH + "/login")
	if err != nil {
		rcfg.Logger.Fatalf("invalid url parsing", err)
	}
	query := encodedUrl.Query()
	query.Add(REDIRECT_HOSTNAME, context.Request.Header.Get("X-Forwarded-Host"))
	query.Add(REDIRECT_PROTO, context.Request.Header.Get("X-Forwarded-Proto"))
	query.Add(REDIRECT_URI, context.Request.RequestURI)
	encodedUrl.RawQuery = query.Encode()

	context.Redirect(http.StatusTemporaryRedirect, encodedUrl.String())
}
