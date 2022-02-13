package openid

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"testing"
	"time"
)

type JWKS struct {
	pk     *rsa.PrivateKey
	signer jose.Signer
}

var jwks *JWKS
var DebugKey = false

type JWKSHandler struct {
}

func (j *JWKS) Init() error {
	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	j.pk = pk

	signer, err := jose.NewSigner(
		jose.SigningKey{Key: j.pk, Algorithm: jose.RS256},
		&jose.SignerOptions{EmbedJWK: false},
	)

	if err != nil {
		return err
	}

	j.signer = signer

	return nil
}

func (j JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	var keys []jose.JSONWebKey
	keys = append(keys, jose.JSONWebKey{KeyID: "testkey",
		Algorithm: "RS256",
		Key:       jwks.pk.Public(),
	})
	jwks := jose.JSONWebKeySet{Keys: keys}
	body, err := json.Marshal(jwks)
	if err != nil {
		_ = r.Write(bytes.NewBufferString("err"))
	}
	_, _ = w.Write(body)
}

func TestJwtTokenParsing(t *testing.T) {
	listenAddr := ":8012"
	jwks = &JWKS{}
	err := jwks.Init()
	if err != nil {
		t.Error(err)
	}
	s := http.Server{
		Addr:    listenAddr,
		Handler: JWKSHandler{},
	}
	defer s.Close()
	go func() {
		_ = s.ListenAndServe()
	}()

	time.Sleep(10 * time.Millisecond)

	openIdConfig := OpenIDConfig{
		ClientId:     "s6BhdRkqt3",
		ClientSecret: "1234",
		ServerConfig: &OpenIDConfigurationResponse{
			Issuer:                    "http://server.example.com",
			JWKSUri:                   "http://" + "127.0.0.1" + listenAddr + "/jwks",
			IDTokenSignAlgSupported:   []string{"RS256"},
			TokenAuthSignAlgSupported: []string{"RS256"},
		},
	}

	_ = "af0ifjsldkj"
	nonce := "n-0S6_WzA2Mj"

	claims := jwt.MapClaims{
		"iss":   "http://server.example.com",
		"sub":   "248289761001",
		"aud":   "s6BhdRkqt3",
		"nonce": "n-0S6_WzA2Mj",
		"exp":   1311281970,
		"iat":   1311280970,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "testkey"

	jwtString, err := token.SignedString(jwks.pk)

	if DebugKey {
		publicKeyData := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&jwks.pk.PublicKey),
			},
		)
		privateKeyData := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(jwks.pk),
			},
		)
		fmt.Printf("pem: \n%v\n", string(publicKeyData))
		fmt.Printf("pem: \n%v\n", string(privateKeyData))
	}

	if err != nil {
		t.Error(err)
	}

	jwt.TimeFunc = time.Unix(1311280970, 0).Local
	token, err = jwt.Parse(jwtString, ParseOpenIdToken(&openIdConfig, nonce))
	if err != nil {
		t.Fatalf("unable to parse JWT: %v", err)
	}
	assert.True(t, token.Valid)
	fmt.Printf("token=%+v", token)
}
