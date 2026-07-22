package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"netops/backend/models"
)

// SNS sends SMS via Amazon SNS using the `Publish` action.
//
// This file implements AWS Signature Version 4 by hand using only the
// Go stdlib. That keeps the scaffold dependency-free; switch to the
// official aws-sdk-go-v2 if you want STS, IMDS, profile loading, etc.
//
// Required env (read by main.go and passed in here):
//
//	AWS_ACCESS_KEY_ID
//	AWS_SECRET_ACCESS_KEY
//	AWS_REGION              (e.g. us-east-1)
//	SNS_PHONE_NUMBERS       comma-separated E.164 numbers
//	SNS_TOPIC_ARN           optional — publish to a topic instead of phone numbers
type SNS struct {
	accessKey string
	secretKey string
	region    string
	numbers   []string
	topicARN  string
	client    *http.Client
}

func NewSNS(accessKey, secretKey, region, phoneNumbersCSV, topicARN string) *SNS {
	s := &SNS{
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
		topicARN:  topicARN,
		client:    &http.Client{Timeout: 15 * time.Second},
	}
	for _, n := range strings.Split(phoneNumbersCSV, ",") {
		n = strings.TrimSpace(n)
		if n != "" {
			s.numbers = append(s.numbers, n)
		}
	}
	return s
}

func (s *SNS) Name() string { return "sns" }

func (s *SNS) Send(a models.Alert) error {
	if s.accessKey == "" || s.secretKey == "" || s.region == "" {
		return errors.New("aws credentials or region not set")
	}
	if len(s.numbers) == 0 && s.topicARN == "" {
		return errors.New("neither SNS_PHONE_NUMBERS nor SNS_TOPIC_ARN configured")
	}

	body := smsBody(a)
	var firstErr error

	if s.topicARN != "" {
		if err := s.publish(body, "TopicArn", s.topicARN); err != nil {
			firstErr = err
		}
	}
	for _, n := range s.numbers {
		if err := s.publish(body, "PhoneNumber", n); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// publish makes a single SNS Publish call. SNS uses query-string-style
// POST bodies, signed with SigV4.
func (s *SNS) publish(message, destKey, destVal string) error {
	form := url.Values{}
	form.Set("Action", "Publish")
	form.Set("Version", "2010-03-31")
	form.Set("Message", message)
	form.Set(destKey, destVal)

	endpoint := fmt.Sprintf("https://sns.%s.amazonaws.com/", s.region)
	bodyStr := form.Encode()

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(bodyStr))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	if err := signSigV4(req, []byte(bodyStr), s.accessKey, s.secretKey, s.region, "sns", time.Now().UTC()); err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// F-27 class: an error body is diagnostic text, not a payload — read a
		// bounded prefix. A hostile or broken endpoint must not be able to grow
		// an error message without limit.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyMaxBytes))
		return fmt.Errorf("sns %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// ---- AWS SigV4 -------------------------------------------------------------

func signSigV4(req *http.Request, body []byte, accessKey, secretKey, region, service string, t time.Time) error {
	amzDate := t.Format("20060102T150405Z")
	shortDate := t.Format("20060102")

	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.Header.Set("Host", req.Host)

	// Canonical headers — lowercased name, trimmed value, sorted.
	type hpair struct{ k, v string }
	headers := []hpair{
		{"content-type", strings.TrimSpace(req.Header.Get("Content-Type"))},
		{"host", strings.TrimSpace(req.Host)},
		{"x-amz-content-sha256", payloadHash},
		{"x-amz-date", amzDate},
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].k < headers[j].k })

	var canonHeaders, signedHeaders strings.Builder
	for i, h := range headers {
		canonHeaders.WriteString(h.k)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(h.v)
		canonHeaders.WriteByte('\n')
		if i > 0 {
			signedHeaders.WriteByte(';')
		}
		signedHeaders.WriteString(h.k)
	}

	canonReq := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery(req.URL.RawQuery),
		canonHeaders.String(),
		signedHeaders.String(),
		payloadHash,
	}, "\n")

	credScope := strings.Join([]string{shortDate, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		sha256Hex([]byte(canonReq)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), shortDate)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credScope, signedHeaders.String(), signature,
	)
	req.Header.Set("Authorization", auth)
	return nil
}

func canonicalURI(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	// Parse, then re-encode in sorted order, per the SigV4 spec.
	v, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vals := v[k]
		sort.Strings(vals)
		for _, val := range vals {
			if i > 0 || b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(val))
		}
	}
	return b.String()
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
