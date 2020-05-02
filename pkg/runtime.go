package pkg

import (
	"github.com/denysvitali/traefik-dex-auth/pkg/openid"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"net/url"
)

type RuntimeConfig struct {
	Logger         *logrus.Logger
	DexUrl         *url.URL
	TdaUrl         *url.URL
	CookieDomain   string
	HmacKey        []byte
	SessionKey     []byte
	ClientId       string
	ClientSecret   string
	TdaCallbackUrl *url.URL
	Keys           map[string]jose.JSONWebKey
	OpenIdConfig   *openid.OpenIDConfiguration
}
