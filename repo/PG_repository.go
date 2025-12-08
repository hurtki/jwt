package repo

import (
	"database/sql"
	"time"

	"github.com/hurtki/jwt/uuid"
)

type PgRepository struct {
	db *sql.DB
}

func (r *PgRepository) AddRefreshToken(userId int, tokenHash []byte, expiresAt time.Time) error {
	return nil
}

func (r *PgRepository) RevokeToken(uuid uuid.UUID) error {
	return nil
}

func (r *PgRepository) RevokeAllFromUser(userID int) error
