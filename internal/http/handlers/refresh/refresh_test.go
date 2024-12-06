package refresh_test

import (
	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/http/handlers/refresh"
	"auth/internal/http/handlers/refresh/mocks"
	sl "auth/internal/lib/logger/sl/sldiscard"
	"auth/internal/lib/tokens"
	"bytes"
	"encoding/json"
	"errors"

	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtCfg = config.JWT{
		SecretKey:      "secretkey",
		AccessExpires:  300 * time.Second,
		RefreshExpires: 3600 * time.Second,
	}
	goodGUID, _           = uuid.Parse("d952af16-4251-4ab8-818f-3f3aca064256")
	goodIP                = "172.0.0.1"
	anotherIp             = "192.168.0.1"
	badIP                 = "some string"
	goodAccessToken, _    = tokens.GenerateAccessToken(goodGUID, goodIP, "bind key", jwtCfg.AccessExpires, jwtCfg.SecretKey)
	invalidAccessToken, _ = tokens.GenerateAccessToken(goodGUID, goodIP, "bind key", time.Duration(0*time.Second), "some string")
	badGuidAccessToken, _ = jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":      "bad guid",
		"ip":       goodIP,
		"exp":      jwtCfg.AccessExpires,
		"bind_key": "bind key",
	}).SignedString([]byte(jwtCfg.SecretKey))
	goodRefreshToken       = "RefreshToken"
	badRefreshToken        = "some string"
	goodHash, _            = bcrypt.GenerateFromPassword([]byte(goodRefreshToken), 10)
	goodRefreshTokenClaims = database.RefreshClaims{
		Hash:      string(goodHash[:]),
		ExpiresAt: time.Now().Add(time.Duration(jwtCfg.RefreshExpires)),
		BindKey:   "bind key",
		IsRevoked: false,
	}
	revokedRefreshTokenClaims = database.RefreshClaims{
		Hash:      string(goodHash[:]),
		ExpiresAt: time.Now().Add(time.Duration(jwtCfg.RefreshExpires)),
		BindKey:   "bind key",
		IsRevoked: true,
	}
	expRefreshTokenClaims = database.RefreshClaims{
		Hash:      string(goodHash[:]),
		ExpiresAt: time.Now(),
		BindKey:   "bind key",
		IsRevoked: false,
	}
)

func TestRefreshHandler(t *testing.T) {
	cases := []struct {
		name               string
		userIP             string
		accessToken        string
		refreshToken       string
		refreshTokenClaims database.RefreshClaims
		respError          string
		saveError          error
		revokeError        error
		getError           error
		emailError         error
		saveMock           bool
		revokeMock         bool
		getMock            bool
		code               int
	}{
		{
			name:               "Success",
			userIP:             goodIP,
			accessToken:        goodAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: goodRefreshTokenClaims,
			code:               200,
		},
		{
			name:         "Empty IP",
			userIP:       "",
			accessToken:  goodAccessToken,
			refreshToken: goodRefreshToken,

			respError: "Unable to get client IP",
			code:      401,
		},
		{
			name:         "Invalid IP",
			userIP:       badIP,
			accessToken:  goodAccessToken,
			refreshToken: goodRefreshToken,
			respError:    "Invalid client IP",
			code:         401,
		},
		{
			name:         "Access token is empty",
			userIP:       goodIP,
			accessToken:  "",
			refreshToken: goodRefreshToken,
			respError:    "Access token is empty",
			code:         401,
		},
		{
			name:         "Refresh token is empty",
			userIP:       goodIP,
			accessToken:  goodAccessToken,
			refreshToken: "",
			respError:    "Refresh token is empty",
			code:         401,
		},
		{
			name:         "Failed to validate access token",
			userIP:       goodIP,
			accessToken:  invalidAccessToken,
			refreshToken: goodRefreshToken,
			respError:    "Invalid access token",
			code:         401,
		},
		{
			name:               "Failed to send IP warning",
			userIP:             anotherIp,
			accessToken:        goodAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: goodRefreshTokenClaims,
			emailError:         errors.New("some error"),
			code:               200,
		},
		{
			name:               "Invalid GUID",
			userIP:             goodIP,
			accessToken:        badGuidAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: goodRefreshTokenClaims,
			respError:          "Invalid user GUID",
			code:               401,
		},
		{
			name:         "Refresh token does not exist",
			userIP:       goodIP,
			accessToken:  goodAccessToken,
			refreshToken: goodRefreshToken,
			getError:     database.ErrTokenNotFound,
			respError:    "Refresh token does not exist",
			code:         401,
		},
		{
			name:         "Failed to find refresh token",
			userIP:       goodIP,
			accessToken:  goodAccessToken,
			refreshToken: goodRefreshToken,
			getError:     errors.New("some error"),
			respError:    "Unable to find refresh token",
			code:         500,
		},
		{
			name:         "Failed to validate refresh token",
			userIP:       goodIP,
			accessToken:  goodAccessToken,
			refreshToken: badRefreshToken,
			respError:    "Invalid refresh token",
			getMock:      true,
			code:         401,
		},
		{
			name:               "Refresh token is revoked",
			userIP:             goodIP,
			accessToken:        goodAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: revokedRefreshTokenClaims,
			respError:          "Refresh token is revoked",
			getMock:            true,
			code:               401,
		},
		{
			name:               "Refresh token has expired",
			userIP:             goodIP,
			accessToken:        goodAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: expRefreshTokenClaims,
			respError:          "Refresh token has expired",
			getMock:            true,
			revokeMock:         true,
			code:               401,
		},
		{
			name:               "Failed to revoke expired refresh token",
			userIP:             goodIP,
			accessToken:        goodAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: expRefreshTokenClaims,
			revokeError:        errors.New("some error"),
			respError:          "Refresh token has expired",
			getMock:            true,
			code:               401,
		},
		{
			name:               "Failed to save new refresh token",
			userIP:             goodIP,
			accessToken:        goodAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: goodRefreshTokenClaims,
			respError:          "Failed to save new refresh token",
			saveError:          errors.New("some error"),
			getMock:            true,
			code:               500,
		},
		{
			name:               "Failed to revoke used refresh token",
			userIP:             goodIP,
			accessToken:        goodAccessToken,
			refreshToken:       goodRefreshToken,
			refreshTokenClaims: goodRefreshTokenClaims,
			revokeError:        errors.New("some error"),
			getMock:            true,
			saveMock:           true,
			code:               200,
		},
	}

	for _, tc := range cases {
		RefreshTokenStorageMock := mocks.NewRefreshTokenStorage(t)

		if tc.respError == "" || tc.saveError != nil || tc.saveMock {
			RefreshTokenStorageMock.On("SaveRefreshToken", mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("string"), jwtCfg).
				Return(string("bind key"), tc.saveError).
				Once()
		}

		if tc.respError == "" || tc.revokeError != nil || tc.revokeMock {
			RefreshTokenStorageMock.On("RevokeRefreshToken", mock.AnythingOfType("string")).
				Return(tc.revokeError).
				Once()
		}

		if tc.respError == "" || tc.getError != nil || tc.getMock {
			RefreshTokenStorageMock.On("GetRefreshToken", mock.AnythingOfType("string")).
				Return(tc.refreshTokenClaims, tc.getError).
				Once()
		}

		EmailSenderMock := mocks.NewEmailSender(t)
		if tc.emailError != nil {
			EmailSenderMock.On("SendIpWarnig", mock.AnythingOfType("string"), tc.userIP).
				Return(tc.emailError).
				Once()
		}

		reqBody := fmt.Sprintf(`{"access_token": "%s", "refresh_token": "%s"}`, tc.accessToken, tc.refreshToken)

		req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(reqBody)))
		require.NoError(t, err)

		if tc.userIP == "" || tc.userIP == badIP {
			req.RemoteAddr = tc.userIP
		} else {
			req.RemoteAddr = tc.userIP + ":8080"
		}

		rr := httptest.NewRecorder()

		handler := refresh.New(sl.NewDiscardLogger(), RefreshTokenStorageMock, EmailSenderMock, jwtCfg)
		router := chi.NewRouter()
		router.Post("/", handler)

		router.ServeHTTP(rr, req)

		require.Equal(t, tc.code, rr.Code, "Case: %s", tc.name)

		RespBody := rr.Body.String()

		var resp refresh.Response

		require.NoError(t, json.Unmarshal([]byte(RespBody), &resp))

		require.Equal(t, tc.respError, resp.Error, "Case: %s", tc.name)
	}
}
