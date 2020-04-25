package pkg

import (
	"github.com/sirupsen/logrus"
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
}
