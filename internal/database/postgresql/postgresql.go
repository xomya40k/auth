package postgresql

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"auth/internal/config"
	"auth/internal/database"
)

type Database struct {
	db *sql.DB
}

func New(configDb config.Database) (*Database, error) {
	const op = "database.postgresql.New"

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+"password=%s dbname=%s sslmode=disable",
		configDb.Host, configDb.Port, configDb.User, configDb.Password, configDb.Name)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, fmt.Errorf("%s: Can not to connect: %w", op, err)
	}

	stmt, err := db.Prepare(`
    CREATE TABLE IF NOT EXISTS refresh_tokens(
        id SERIAL PRIMARY KEY,
		user_GUID UUID NOT NULL,
		bind_key VARCHAR NOT NULL UNIQUE,
        hash VARCHAR NOT NULL UNIQUE,
		expires_at timestamp with time zone NOT NULL,
        created_at timestamp with time zone NOT NULL,
		is_revoked boolean default(false));`)

	if err != nil {
		return nil, fmt.Errorf("%s: Preparing statement error: %w", op, err)
	}

	_, err = stmt.Exec()
	if err != nil {
		return nil, fmt.Errorf("%s: Executing statement error: %w", op, err)
	}

	return &Database{db: db}, nil
}

func (d *Database) SaveRefreshToken(userGUID uuid.UUID, token string, jwtConfig config.JWT) (string, error) {
	const op = "database.postgresql.SaveRefreshToken"

	stmt, err := d.db.Prepare(`
	INSERT INTO refresh_tokens (user_GUID, hash, bind_key, expires_at, created_at) 
	VALUES ($1, $2, $3, $4, $5);`)

	if err != nil {
		return "", fmt.Errorf("%s: Preparing statement error: %w", op, err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(token), 10)
	if err != nil {
		return "", fmt.Errorf("%s: Creating token hash error: %w", op, err)
	}

	bind_key, err := GenerateBindKey()
	if err != nil {
		return "", fmt.Errorf("%s: Generating bind key error: %w", op, err)
	}

	created_at := time.Now()
	expires_at := created_at.Add(jwtConfig.RefreshExpires)

	_, err = stmt.Exec(userGUID, hash, bind_key, expires_at, created_at)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return "", fmt.Errorf("%s: %w", op, database.ErrTokenExists)
		}

		return "", fmt.Errorf("%s: Executing statement error: %w", op, err)
	}

	return bind_key, nil
}

func (d *Database) GetRefreshToken(bindKey string) (database.RefreshClaims, error) {
	const op = "database.postgresql.GetRefreshToken"

	stmt, err := d.db.Prepare(`SELECT user_GUID, hash, expires_at, is_revoked 
		FROM refresh_tokens WHERE bind_key = $1;`)
	if err != nil {
		return database.RefreshClaims{}, fmt.Errorf("%s: Preparing statement error: %w", op, err)
	}

	var userGUID uuid.UUID
	var hash string
	var expiresAt time.Time
	var isRevoked bool

	err = stmt.QueryRow(bindKey).Scan(&userGUID, &hash, &expiresAt, &isRevoked)
	if errors.Is(err, sql.ErrNoRows) {
		return database.RefreshClaims{}, database.ErrTokenNotFound
	}

	if err != nil {
		return database.RefreshClaims{}, fmt.Errorf("%s: Executing statement error: %w", op, err)
	}

	refreshToken := database.RefreshClaims{
		UserGUID:  userGUID,
		Hash:      hash,
		BindKey:   bindKey,
		ExpiresAt: expiresAt.Local(),
		IsRevoked: isRevoked,
	}

	return refreshToken, nil
}

func (d *Database) RevokeRefreshToken(bindKey string) error {
	const op = "database.postgresql.GetRefreshToken"

	stmt, err := d.db.Prepare(`
	UPDATE refresh_tokens
	SET is_revoked = true
	WHERE bind_key = $1;`)
	if err != nil {
		return fmt.Errorf(`%s: Can not to revoke fresh token with bind key: 
		"%s": Preparing statement error: %w`, op, bindKey, err)
	}

	_, err = stmt.Exec(bindKey)
	if errors.Is(err, sql.ErrNoRows) {
		return database.ErrTokenNotFound
	}

	if err != nil {
		return fmt.Errorf(`%s: Can not to revoke fresh token with bind key: 
		"%s": Executing statement error: %w`, op, bindKey, err)
	}

	return nil
}

func GenerateBindKey() (string, error) {
	const op = "database.postgresql.GenerateBindKey"

	rb := make([]byte, 16)
	_, err := rand.Read(rb)
	if err != nil {
		return "", fmt.Errorf("%s: Failed to get random bytes: %w", op, err)
	}

	return base64.URLEncoding.EncodeToString(rb), nil
}
