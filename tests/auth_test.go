package auth_test

import (
	"auth/internal/http/handlers/refresh"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/gavv/httpexpect"
	"github.com/google/uuid"
)

var (
	host = "localhost:8080"
	guid = uuid.New().String()
)

func TestAuth(t *testing.T) {
	url := url.URL{
		Scheme: "http",
		Host:   host,
	}

	httpExpect := httpexpect.New(t, url.String())

	requestExpect := httpExpect.GET("/" + guid)

	responseExpect := requestExpect.Expect()
	responseExpect.Status(200).
		JSON().Object().
		ContainsKey("access_token").
		ContainsKey("refresh_token")

	getResponse := responseExpect.Body().Raw()

	data := refresh.Request{}
	json.Unmarshal([]byte(getResponse), &data)

	httpExpect.POST("/").
		WithJSON(data).
		Expect().
		Status(200).
		JSON().Object().
		ContainsKey("access_token").
		ContainsKey("refresh_token")
}
