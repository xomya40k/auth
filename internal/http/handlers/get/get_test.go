package get_test

import (
	"auth/internal/config"
	"auth/internal/http/handlers/get"
	"auth/internal/http/handlers/get/mocks"
	sl "auth/internal/lib/logger/sl/sldiscard"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	jwtCfg = config.JWT{
		SecretKey:      "secretkey",
		AccessExpires:  300 * time.Second,
		RefreshExpires: 3600 * time.Second,
	}
	goodGUID = "d952af16-4251-4ab8-818f-3f3aca064256"
	badGUID  = "some string"
	goodIP   = "172.0.0.0:8080"
	badIP    = "some string"
)

func TestGetHandler(t *testing.T) {
	cases := []struct {
		name      string
		userGUID  string
		userIP    string
		respError string
		saveError error
		code      int
	}{
		{
			name:     "Success",
			userGUID: goodGUID,
			userIP:   "172.0.0.0:8080",
			code:     200,
		},
		{
			name:      "Invalid GUID",
			userGUID:  badGUID,
			userIP:    goodIP,
			respError: "Invalid user GUID",
			code:      401,
		},
		{
			name:      "Empty IP",
			userGUID:  goodGUID,
			userIP:    "",
			respError: "Unable to get client IP",
			code:      401,
		},
		{
			name:      "Invalid IP",
			userGUID:  goodGUID,
			userIP:    badIP,
			respError: "Invalid client IP",
			code:      401,
		},
		{
			name:      "Failed to save refresh token",
			userGUID:  goodGUID,
			userIP:    goodIP,
			respError: "Failed to save refresh token",
			saveError: errors.New("Some error"),
			code:      500,
		},
	}

	for _, tc := range cases {
		RefreshTokenStorageMock := mocks.NewRefreshTokenStorage(t)

		if tc.respError == "" || tc.saveError != nil {
			guid, _ := uuid.Parse(tc.userGUID)
			RefreshTokenStorageMock.On("SaveRefreshToken", guid, mock.AnythingOfType("string"), jwtCfg).
				Return(string("some_string"), tc.saveError).
				Once()
		}

		url := fmt.Sprintf(`/%s`, tc.userGUID)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		req.RemoteAddr = tc.userIP

		rr := httptest.NewRecorder()

		handler := get.New(sl.NewDiscardLogger(), RefreshTokenStorageMock, jwtCfg)
		router := chi.NewRouter()
		router.Get("/{user_guid}", handler)

		router.ServeHTTP(rr, req)

		require.Equal(t, tc.code, rr.Code)

		body := rr.Body.String()

		var resp get.Response

		require.NoError(t, json.Unmarshal([]byte(body), &resp))

		require.Equal(t, tc.respError, resp.Error)
	}
}
