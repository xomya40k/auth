package get

import (
	"log/slog"
	"net"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/google/uuid"

	"auth/internal/config"
	resp "auth/internal/lib/api/response"
	"auth/internal/lib/logger/sl"
	"auth/internal/lib/tokens"
)

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenStorage interface {
	SaveRefreshToken(userGUID uuid.UUID, token string, jwtConfig config.JWT) (string, error)
	RevokeRefreshToken(bindKey string) error
}

func New(log *slog.Logger, refreshTokenStorage RefreshTokenStorage, jwtConfig config.JWT) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.auth.get.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		userGUID, err := uuid.Parse(chi.URLParam(r, "user_guid"))
		if err != nil {
			log.Error("Failed to parse user_guid", sl.Err(err))
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Invalid user GUID"))
			return
		}

		userIp := r.RemoteAddr
		if userIp == "" {
			log.Error("Remote address is empty")
			render.Status(r, 401)
			render.JSON(w, r, resp.Error("Can not to get client IP"))
			return
		} else {
			userIp, _, err = net.SplitHostPort(userIp)
			if err != nil {
				log.Error("Failed to parse client IP", sl.Err(err))
				render.Status(r, 401)
				render.JSON(w, r, resp.Error("Invalid client IP"))
				return
			}
		}

		refreshToken, err := tokens.GenerateRefreshToken()
		if err != nil {
			log.Error("Failed to generate refresh token", sl.Err(err))
			render.Status(r, 500)
			render.JSON(w, r, resp.Error("Failed to generate refresh token"))
			return
		}

		bindKey, err := refreshTokenStorage.SaveRefreshToken(userGUID, refreshToken, jwtConfig)
		if err != nil {
			log.Error("Failed to save refresh token", sl.Err(err))
			render.Status(r, 500)
			render.JSON(w, r, resp.Error("Failed to save refresh token"))
			return
		}

		accessToken, err := tokens.GenerateAccessToken(userGUID, userIp, bindKey,
			jwtConfig.AccessExpires, jwtConfig.SecretKey)
		if err != nil {
			log.Error("Failed to save access token", sl.Err(err))
			err = refreshTokenStorage.RevokeRefreshToken(bindKey)
			if err != nil {
				log.Error("Failed to revoke refresh token", sl.Err(err))
			}
			render.Status(r, 500)
			render.JSON(w, r, resp.Error("Failed to generate access token"))
			return
		}

		responseOK(w, r, accessToken, refreshToken)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, accessToken string, refreshToken string) {
	render.JSON(w, r, Response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
