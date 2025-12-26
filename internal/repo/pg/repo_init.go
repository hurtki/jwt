package pg_repo

import (
	"database/sql"
	"fmt"
)

func NewAuthRepo(db *sql.DB) (*PgRepository, error) {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id SERIAL PRIMARY KEY,
		user_id INT NOT NULL,
		token_b64_hash TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL,
		revoked_at TIMESTAMPTZ
	);

	CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_b64_hash);
	CREATE INDEX IF NOT EXISTS dx_refresh_expires_at ON refresh_tokens(expires_at);
	`)

	if err != nil {
		return nil, fmt.Errorf("cannot create refresh tokens table: %s", err.Error())
	}

	return &PgRepository{
		db: db,
	}, nil
}
