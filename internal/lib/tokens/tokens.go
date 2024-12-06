package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrAccessTokenExpired = errors.New("access token is expired")
)

func GenerateAccessToken(userGUID uuid.UUID, userIp string, bind_key string,
	timeExpires time.Duration, key string) (string, error) {
	const op = "lib.auth.token.GenerateAccessToken"

	accessExpires := time.Now().Add(timeExpires)

	accessPayload := jwt.MapClaims{
		"sub":      userGUID,
		"ip":       userIp,
		"exp":      accessExpires.Unix(),
		"bind_key": bind_key,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, accessPayload)

	accessToken, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("%s: Signing token error: %w", op, err)
	}

	return accessToken, nil
}

func GenerateRefreshToken() (string, error) {
	const op = "lib.auth.token.GenerateRefreshToken"

	rb := make([]byte, 32)
	_, err := rand.Read(rb)
	if err != nil {
		return "", fmt.Errorf("%s: Failed to get random bytes: %w", op, err)
	}

	refreshToken := base64.URLEncoding.EncodeToString(rb)

	return refreshToken, nil
}

func ValidateRefreshToken(refreshToken string, hash string) error {
	const op = "lib.auth.token.ValidateRefreshToken"

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(refreshToken))
	if err != nil {
		return fmt.Errorf("%s: Failed to validate refresh token: %v", op, err)
	}

	return nil
}

func ValidateAccessToken(accessToken string, key []byte) (jwt.MapClaims, error) {
	const op = "lib.auth.token.ValidateAccessToken"

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%s: Unexpected signing method: %v", op, token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			err = ErrAccessTokenExpired
		} else {
			return nil, fmt.Errorf("%s: Parsing access token error: %v", op, err)
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%s: Unexpected token type", op)
	}

	return claims, err
}
