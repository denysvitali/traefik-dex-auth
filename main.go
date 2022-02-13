package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/alexflint/go-arg"
	"github.com/dchest/uniuri"
	"github.com/denysvitali/traefik-dex-auth/pkg"
	"github.com/denysvitali/traefik-dex-auth/pkg/auth"
	"github.com/denysvitali/traefik-dex-auth/pkg/openid"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var rcfg *pkg.RuntimeConfig
var openIdConfig *openid.OpenIDConfig

const BasePath = "/traefik-dex-auth"
const GenericError = "internal server error"
const UserError = "bad request"

func main() {
	var args struct {
		ClientID     string `arg:"env:CLIENT_ID" default:"traefik-dex-auth" help:"Client ID used to identify this service with Dex"`
		ClientSecret string `arg:"env:CLIENT_SECRET" help:"Client Secret set in the Dex config"`
		DexUrl       string `arg:"env:DEX_URL" help:"Base URL of your Dex instance (e.g: http://127.0.0.1:5556)"`
		TDAUrl       string `arg:"env:TDA_URL" help:"Url of the Traefik Dex Auth instance (e.g: https://auth.example.com)"`
		CookieDomain string `arg:"env:COOKIE_DOMAIN" help:"Domain of application for the authentication cookie (e.g: .example.com)"`
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
	rcfg = &pkg.RuntimeConfig{
		Logger:         log,
		DexUrl:         dexUrl,
		TdaUrl:         tdaUrl,
		HmacKey:        hmacKey,
		SessionKey:     sessionKey,
		CookieDomain:   args.CookieDomain,
		TdaCallbackUrl: nil,
	}

	openIdConfig = &openid.OpenIDConfig{
		Keys:         map[string]jose.JSONWebKey{},
		ClientId:     args.ClientID,
		ClientSecret: args.ClientSecret,
	}

	log.Debugf("sessionKey=%v", sessionKey)
	TdaCallbackUrl, err := rcfg.TdaUrl.Parse(BasePath + "/callback")
	if err != nil {
		logrus.Fatalf("unable to parse callback url: %v", err)
	}

	rcfg.TdaCallbackUrl = TdaCallbackUrl

	r := gin.Default()
	r.GET(BasePath+"/login", handleLogin)
	r.GET(BasePath+"/callback", handleCallback)
	r.Any("/", handleAny)

	err = r.Run()
	if err != nil {
		logrus.Fatal(err)
	}
}

func handleLogin(context *gin.Context) {
	err := checkCookie(context)
	if err == nil {
		return
	}

	dexAuth, err := rcfg.DexUrl.Parse("/auth")
	if err != nil {
		rcfg.Logger.Errorf("unable to parse DEX url: %v", err)
		context.String(http.StatusInternalServerError, GenericError)
		return
	}
	dexAuth.Query().Add("response_type", "code")
	dexAuth.Query().Add("client_id", openIdConfig.ClientId)

	// Generate sessionNonce and sessionState to avoid replay attacks
	sessionNonce := uniuri.NewLen(25)
	sessionState := uniuri.NewLen(25)

	dexValues := dexAuth.Query()
	dexValues.Add("scope", "openid profile email")
	dexValues.Add("response_type", "code")
	dexValues.Add("client_id", openIdConfig.ClientId)
	dexValues.Add("redirect_uri", rcfg.TdaCallbackUrl.String())
	dexValues.Add("state", sessionState) // CSRF,XSRF mitigation
	dexValues.Add("nonce", sessionNonce) // replay attacks mitigation

	dexAuth.RawQuery = dexValues.Encode()

	originalQuery := context.Request.URL.Query()
	finalAuthString, err := auth.CreateAuthInfoCookie(rcfg.HmacKey, originalQuery)

	context.SetCookie(auth.TdaSessionInfoCookie, finalAuthString, 60, "", rcfg.CookieDomain, true, true)
	context.SetCookie(auth.TdaSessionNonceCookie, sessionNonce, auth.CookieLengthSeconds, "", rcfg.CookieDomain, true, true)
	context.SetCookie(auth.TdaSessionStateCookie, sessionState, 60, "", rcfg.CookieDomain, true, true)
	context.SetSameSite(http.SameSiteStrictMode)
	context.Redirect(http.StatusTemporaryRedirect, dexAuth.String())
}

func checkCookie(context *gin.Context) error {
	// Cookie set, let's check whether it's valid or not
	authCookie, err := context.Cookie(auth.TdaAuthCookie)
	if err != nil {
		return err
	}

	sessionNonceCookie, err := context.Cookie(auth.TdaSessionNonceCookie)
	if err != nil {
		return err
	}

	rcfg.Logger.Debugf("Cookie content=%v", authCookie)
	// JWK validation
	jwtString := authCookie
	_, err = getOpenIdConfig(rcfg)
	token, err := jwt.Parse(jwtString, openid.ParseOpenIdToken(openIdConfig, sessionNonceCookie))
	if err != nil {
		return err
	}
	rcfg.Logger.Debugf("Token=%v, Claims=%v", token, token.Claims.(jwt.MapClaims))

	if token.Valid {
		// token.Claims.(jwt.MapClaims)["groups"]
		context.String(http.StatusOK, "success")
		return nil
	}
	return errors.New("invalid token")
}

func handleCallback(context *gin.Context) {
	code := context.Query("code")
	state := context.Query("state")
	sessionState, err := context.Cookie(auth.TdaSessionStateCookie)
	if err != nil {
		rcfg.Logger.Errorf("%s cookie missing: %v", auth.TdaSessionStateCookie, err)
		context.String(http.StatusInternalServerError, GenericError)
		return
	}
	sessionNonce, err := context.Cookie(auth.TdaSessionNonceCookie)
	if err != nil {
		rcfg.Logger.Errorf("%s cookie missing: %v", auth.TdaSessionNonceCookie, err)
		context.String(http.StatusInternalServerError, GenericError)
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
	openIdConfigServer, err := getOpenIdConfig(rcfg)
	if err != nil {
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	if openIdConfigServer.TokenEndpoint == "" {
		rcfg.Logger.Error("Oauth 2.0 Token endpoint missing")
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("redirect_uri", rcfg.TdaCallbackUrl.String())
	values.Add("client_id", openIdConfig.ClientId)
	values.Add("client_secret", openIdConfig.ClientSecret)
	encodedData := values.Encode()

	req, _ := http.NewRequest("POST",
		openIdConfigServer.TokenEndpoint,
		strings.NewReader(encodedData),
	)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encodedData)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		rcfg.Logger.Errorf("unable to perform /token request: %v", err)
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		rcfg.Logger.Errorf("unable to read body bytes: %v", err)
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	if resp.StatusCode == 400 {
		var oauthErr openid.Oauth2TokenErrorResponse
		err = json.Unmarshal(bodyBytes, &oauthErr)
		rcfg.Logger.Errorf("token retrieval failed: %v", oauthErr)
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	if resp.StatusCode != 200 {
		rcfg.Logger.Errorf("invalid status code %d, body=%v", resp.StatusCode, string(bodyBytes))
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	var oauth2TokenResponse openid.OpenIDTokenResponse
	err = json.Unmarshal(bodyBytes, &oauth2TokenResponse)
	if err != nil {
		rcfg.Logger.Errorf("unable to unmarshal oauth2 token response: %v", err)
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	token, err := jwt.Parse(oauth2TokenResponse.IdToken, openid.ParseOpenIdToken(openIdConfig, sessionNonce))

	if err != nil {
		rcfg.Logger.Errorf("unable to decode token: %v, token=%v", err, token)
		context.String(http.StatusInternalServerError, GenericError)
		return
	}

	if !token.Valid {
		rcfg.Logger.Error("invalid token")
		context.String(http.StatusForbidden, "invalid token")
		return
	}

	context.SetSameSite(http.SameSiteDefaultMode)
	context.SetCookie(auth.TdaAuthCookie, oauth2TokenResponse.IdToken,
		oauth2TokenResponse.ExpiresIn,
		"",
		rcfg.CookieDomain, true, true)

	// Decode Auth Info
	val, err := context.Cookie(auth.TdaSessionInfoCookie)
	if err != nil {
		context.String(http.StatusOK, "auth successful, missing callback")
		return
	}

	redirectURL, err := auth.ParseCookie(rcfg.HmacKey, val)
	if err != nil {
		rcfg.Logger.Warnf("unable to parse cookie: %v", err)
		context.String(http.StatusBadRequest, "bad request")
	}

	context.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func getOpenIdConfig(config *pkg.RuntimeConfig) (*openid.OpenIDConfigurationResponse, error) {
	if openIdConfig.ServerConfig != nil {
		return openIdConfig.ServerConfig, nil
	}
	openIdConfigUrl, err := config.DexUrl.Parse("/.well-known/openid-configuration")
	if err != nil {
		config.Logger.Errorf("unable to determine openid-configuration URL: %v", err)
		return nil, err
	}

	resp, err := http.Get(openIdConfigUrl.String())
	if err != nil {
		config.Logger.Errorf("unable to get openId Config: %v", err)
		return nil, err
	}

	var serverOpenIdConfig openid.OpenIDConfigurationResponse
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		config.Logger.Errorf("unable to read openid config request body: %v", err)
		return nil, err
	}
	err = json.Unmarshal(bodyBytes, &serverOpenIdConfig)
	if err != nil {
		config.Logger.Errorf("unable to unmarshal json: %v", err)
		return nil, err
	}

	openIdConfig.ServerConfig = &serverOpenIdConfig
	return &serverOpenIdConfig, nil
}

func handleAny(context *gin.Context) {
	rcfg.Logger.Debugf("Handling \"ANY\":")
	rcfg.Logger.Debugf("\tHeaders: %v", context.Request.Header)

	encodedUrl, err := rcfg.TdaUrl.Parse(BasePath + "/login")
	if err != nil {
		rcfg.Logger.Fatalf("invalid url parsing: %v", err)
	}
	urlQuery := encodedUrl.Query()
	urlQuery.Add(auth.RedirectHostname, context.Request.Header.Get("X-Forwarded-Host"))
	urlQuery.Add(auth.RedirectProto, context.Request.Header.Get("X-Forwarded-Proto"))
	urlQuery.Add(auth.RedirectUri, context.Request.RequestURI)
	encodedUrl.RawQuery = urlQuery.Encode()

	err = checkCookie(context)
	if err != nil {
		rcfg.Logger.Debugf("handleAny, checkCookie returned %v, redirecting", err)
		context.Redirect(http.StatusTemporaryRedirect, encodedUrl.String())
	}
}
