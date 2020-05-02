package auth

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"github.com/gorilla/schema"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const RedirectUri = "redirect_uri"
const RedirectHostname = "redirect_hostname"
const RedirectProto = "redirect_proto"

const RedirectTimeout = 5 * 60 // 5 minutes timeout for the redirection to happen based on cookies

type AuthInfo struct {
	Hostname  string `schema:"hostname"`
	Proto     string `schema:"proto"`
	Uri       string `schema:"uri"`
	Timestamp int64  `schema:"ts"`
}

func ParseCookie(HmacKey []byte, cookieValue string) (string, error) {
	infoMatcher := regexp.MustCompile("^(.*?)\\|(.*?)$")
	if !infoMatcher.MatchString(cookieValue) {
		return "", errors.New("invalid cookie format")
	}

	submatches := infoMatcher.FindStringSubmatch(cookieValue)
	encodedQueryBase64 := submatches[1]
	hmacString := submatches[2]

	logrus.Debugf("encodedQueryBase64=%v, hmacString=%v",
		encodedQueryBase64,
		hmacString)

	queryBytes, err := base64.StdEncoding.DecodeString(encodedQueryBase64)
	if err != nil {
		return "", errors.New("unable to decode Base64")
	}

	mac := hmac.New(sha512.New, HmacKey)
	mac.Reset()
	mac.Write(queryBytes)
	macBytes := mac.Sum(nil)

	if base64.StdEncoding.EncodeToString(macBytes) != hmacString {
		return "", errors.New("invalid MAC")
	}

	queryValues, err := url.ParseQuery(string(queryBytes))
	if err != nil {
		return "", errors.New("unable to parse url query")
	}

	var authInfo AuthInfo
	err = schema.NewDecoder().Decode(&authInfo, queryValues)
	if err != nil {
		return "", err
	}

	nowTS := time.Now().Unix()
	if authInfo.Timestamp > nowTS || nowTS - authInfo.Timestamp > RedirectTimeout {
		return "", errors.New("redirection timeout")
	}

	location := url.URL{
		Host:   authInfo.Hostname,
		Path:   authInfo.Uri,
		Scheme: authInfo.Proto,
	}

	return location.String(), nil
}

func CreateAuthInfoCookie(hmacKey []byte, originalQuery url.Values) (string, error) {
	var authInfoEncoded = make(map[string][]string)
	err := schema.NewEncoder().Encode(AuthInfo{
		Hostname: originalQuery.Get(RedirectHostname),
		Proto: originalQuery.Get(RedirectProto),
		Uri: originalQuery.Get(RedirectUri),
		Timestamp: time.Now().Unix(),
	}, authInfoEncoded)

	encodedQuery := url.Values(authInfoEncoded).Encode()

	if err != nil {
		return "", err
	}

	encodedQueryBytes, err := ioutil.ReadAll(strings.NewReader(encodedQuery))
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha512.New, hmacKey)
	mac.Reset()
	mac.Write(encodedQueryBytes)
	macBytes := mac.Sum(nil)

	macString := base64.StdEncoding.EncodeToString(macBytes)
	encodedQueryB64 := base64.StdEncoding.EncodeToString(encodedQueryBytes)

	// Authenticated string
	return encodedQueryB64 + "|" + macString, nil
}
