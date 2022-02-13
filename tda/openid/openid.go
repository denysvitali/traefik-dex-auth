package openid

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"net/http"
)

type OpenIDConfigurationResponse struct {
	Issuer                        string   `json:"issuer"`
	AuthEndpoint                  string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                 string   `json:"token_endpoint,omitempty"`
	UserInfoEndpoint              string   `json:"userinfo_endpoint,omitempty"`
	CheckSessionIframe            string   `json:"check_session_iframe,omitempty"`
	EndSessionEndpoint            string   `json:"end_session_endpoint,omitempty"`
	JWKSUri                       string   `json:"jwks_uri"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	ACRValuesSupported            []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported         []string `json:"subject_types_supported"`
	UserInfoSignAlgSupported      []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserInfoEncAlgSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	IDTokenSignAlgSupported       []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncAlgSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	RequestObjectSignAlgSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncAlgSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	TokenAuthMethodSupported      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenAuthSignAlgSupported     []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported        []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported           []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported               []string `json:"claims_supported,omitempty"`
	ServiceDocumentation          []string `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported        []string `json:"claims_locales_supported,omitempty"`
	UiLocalesSupported            []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported      []string `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported     []string `json:"request_parameter_supported,omitempty"`
	RequestUriParameterSupported  []string `json:"request_uri_parameter_supported,omitempty"`
	RequestUriRegistration        []string `json:"require_request_uri_registration,omitempty"`
	OpPolicyUri                   []string `json:"op_policy_uri,omitempty"`
	OpTosUri                      []string `json:"op_tos_uri,omitempty"`
}

type Oauth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type Oauth2TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorUri         string `json:"error_uri,omitempty"`
}

type OpenIDTokenResponse struct {
	Oauth2TokenResponse
	IdToken string `json:"id_token"`
}

type OpenIDClaims struct {
	jwt.MapClaims
}

type OpenIDConfig struct {
	Keys         map[string]jose.JSONWebKey
	ClientId     string
	ClientSecret string

	ServerConfig *OpenIDConfigurationResponse
}

func (c OpenIDClaims) Valid() error {
	// Check if the key is valid
	logrus.Debugf("checking claims %v", c)
	return nil
}

func ParseOpenIdToken(oidcConfig *OpenIDConfig, nonce string) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		tokenAlg := token.Header["alg"]
		var validTokenAlg = false
		for _, supportedAlg := range oidcConfig.ServerConfig.IDTokenSignAlgSupported {
			if supportedAlg == tokenAlg {
				validTokenAlg = true
			}
		}

		if oidcConfig.Keys == nil {
			oidcConfig.Keys = map[string]jose.JSONWebKey{}
		}

		keyId := token.Header["kid"].(string)
		var key *jose.JSONWebKey
		if val, ok := oidcConfig.Keys[keyId]; ok {
			key = &val
		} else {
			// Get and cache the key
			jwks, err := getJWKS(oidcConfig.ServerConfig.JWKSUri)
			if err != nil {
				return nil, err
			}

			keys := jwks.Key(token.Header["kid"].(string))
			if len(keys) != 1 {
				return nil, errors.New("invalid key id")
			}
			key = &keys[0]

			if !key.Valid() {
				return nil, errors.New("key is invalid")
			}

			// Key is valid, let's cache it
			oidcConfig.Keys[keyId] = *key
		}

		if !validTokenAlg {
			errorMessage := fmt.Sprintf(
				"invalid token alg, supported token algs are %v",
				oidcConfig.ServerConfig.IDTokenSignAlgSupported,
			)
			return nil, errors.New(errorMessage)
		}

		claims := token.Claims.(jwt.MapClaims)
		if !claims.VerifyIssuer(oidcConfig.ServerConfig.Issuer, true) {
			token.Valid = false
			return nil, errors.New("invalid token issuer")
		}

		if !claims.VerifyAudience(oidcConfig.ClientId, true) {
			token.Valid = false
			return nil, errors.New("invalid token audience")
		}

		if claims["nonce"] != nonce {
			token.Valid = false
			return nil, errors.New("invalid nonce")
		}

		err := claims.Valid()
		if err != nil {
			return nil, err
		}

		token.Valid = true

		_ = token.Claims.(jwt.MapClaims)
		return key.Key, nil
	}
}

func getJWKS(uri string) (*jose.JSONWebKeySet, error) {
	// Get key
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(bodyBytes, &jwks)
	if err != nil {
		return nil, err
	}

	return &jwks, nil
}
