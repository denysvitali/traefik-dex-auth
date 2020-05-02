package auth

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func TestCookie(t *testing.T) {
	values := url.Values {}
	values.Set(RedirectHostname,"example.com")
	values.Set(RedirectProto, "https")
	values.Set(RedirectUri, "/path/to/resource")

	hmacKey := []byte("abcdef")
	cookieValue, err := CreateAuthInfoCookie(hmacKey, values)
	assert.Nil(t, err)

	urlString, err := ParseCookie(hmacKey, cookieValue)
	assert.Nil(t, err)
	assert.Equal(t, "https://example.com/path/to/resource", urlString)

}