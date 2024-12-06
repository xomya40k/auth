package refresh

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/google/uuid"

	"auth/internal/config"
	"auth/internal/database"
	resp "auth/internal/lib/api/response"
	"auth/internal/lib/logger/sl"
	"auth/internal/lib/tokens"
)

type Request struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenStorage interface {
	SaveRefreshToken(user_GUID uuid.UUID, token string, jwtConfig config.JWT) (string, error)
	RevokeRefreshToken(bindKey string) error
	GetRefreshToken(bindKey string) (database.RefreshClaims, error)
}

type EmailSender interface {
	SendIpWarnig(to, ip string) error
}

func New(log *slog.Logger, refreshTokenStorage RefreshTokenStorage, emailSender EmailSender, jwtConfig config.JWT) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.auth.refresh.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		userIp := r.RemoteAddr
		if userIp == "" {
			log.Error("Remote address is empty")
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Can not to get client IP"))
			return
		} else {
			var err error
			userIp, _, err = net.SplitHostPort(userIp)
			if err != nil {
				log.Error("Failed to parse client IP", sl.Err(err))
				render.Status(r, 401)
				render.JSON(w, r, resp.Error("Invalid client IP"))
				return
			}
		}

		var req Request

		err := render.DecodeJSON(r.Body, &req)
		if errors.Is(err, io.EOF) {
			log.Error("Request body is empty")
			render.Status(r, 400)
			render.JSON(w, r, resp.Error("Empty request"))
			return
		}

		if err != nil {
			log.Error("Failed to decode request body", sl.Err(err))
			render.Status(r, 400)
			render.JSON(w, r, resp.Error("Failed to decode request"))
			return
		}

		accessToken := req.AccessToken
		if accessToken == "" {
			log.Error("Access token is empty")
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Access token is empty"))
			return
		}

		refreshToken := req.RefreshToken
		if refreshToken == "" {
			log.Error("Refresh token is empty")
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Refresh token is empty"))
			return
		}

		accessClaims, err := tokens.ValidateAccessToken(accessToken, []byte(jwtConfig.SecretKey))
		if err != nil && !errors.Is(err, tokens.ErrAccessTokenExpired) {
			log.Error("Failed to validate access token", sl.Err(err))
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Invalid access token"))
			return
		}

		bindKey := accessClaims["bind_key"].(string)
		previousIP := accessClaims["ip"].(string)

		if previousIP != userIp {
			err = emailSender.SendIpWarnig("user@mail", userIp)
			if err != nil {
				log.Error("Failed to send IP warning", sl.Err(err))
			}
		}

		userGUID, err := uuid.Parse(accessClaims["sub"].(string))
		if err != nil {
			log.Error("Failed to parse user GUID", sl.Err(err))
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Invalid user GUID"))
			return
		}

		refreshClaims, err := refreshTokenStorage.GetRefreshToken(bindKey)
		if err != nil {
			log.Error("Failed to find refresh token", sl.Err(err))
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Refresh token does not exist"))
			return
		}

		err = tokens.ValidateRefreshToken(refreshToken, refreshClaims.Hash)
		if err != nil {
			log.Error("Failed to validate refresh token", sl.Err(err))
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Invalid refresh token"))
			return
		}

		if refreshClaims.IsRevoked {
			log.Error("Refresh token is revoked")
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Refresh token is revoked"))
			return
		} else if refreshClaims.ExpiresAt.Before(time.Now()) {
			log.Error("Refresh token has expired")

			err = refreshTokenStorage.RevokeRefreshToken(bindKey)
			if err != nil {
				log.Error("Failed to revoke refresh token", sl.Err(err))
			}

			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Refresh token has expired"))
			return
		}

		newRefreshToken, err := tokens.GenerateRefreshToken()
		if err != nil {
			log.Error("Failed to generate new refresh token", sl.Err(err))
			render.Status(r, 500)
			render.JSON(w, r, resp.Error("Failed to generate new refresh token"))
			return
		}

		usedBindKey := bindKey
		newBindKey, err := refreshTokenStorage.SaveRefreshToken(userGUID, newRefreshToken, jwtConfig)
		if err != nil {
			log.Error("Failed to save new refresh token", sl.Err(err))
			render.Status(r, 500)
			render.JSON(w, r, resp.Error("Failed to save new refresh token"))
			return
		}

		newAccessToken, err := tokens.GenerateAccessToken(userGUID, userIp, newBindKey,
			jwtConfig.AccessExpires, jwtConfig.SecretKey)
		if err != nil {
			log.Error("Failed to save access token", sl.Err(err))
			err = refreshTokenStorage.RevokeRefreshToken(newBindKey)
			if err != nil {
				log.Error("Failed to revoke refresh token", sl.Err(err))
			}
			render.Status(r, 500)
			render.JSON(w, r, resp.Error("Failed to generate new access token"))
			return
		}

		err = refreshTokenStorage.RevokeRefreshToken(usedBindKey)
		if err != nil {
			log.Error("Failed to revoke used refresh token", sl.Err(err))
		}

		responseOK(w, r, newAccessToken, newRefreshToken)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, accessToken string, refreshToken string) {
	render.JSON(w, r, Response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
