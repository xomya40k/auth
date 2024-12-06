package database

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type RefreshClaims struct {
	UserGUID  uuid.UUID
	BindKey   string
	Hash      string
	ExpiresAt time.Time
	IsRevoked bool
}

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExists   = errors.New("token exists")
)
