package pg_repo

import (
	"database/sql"
	"time"

	"github.com/hurtki/jwt/repo"
)

type PgRepository struct {
	db *sql.DB
}

func (r *PgRepository) AddRefreshToken(userId int, tokenB64Hash string, expiresAt time.Time) error {

	_, err := r.db.Exec(`
	INSERT INTO refresh_tokens (user_id, token_b64_hash, expires_at)
	VALUES ($1, $2, $3);
	`, userId, tokenB64Hash, expiresAt)

	return toRepoError(err)
}

func (r *PgRepository) RevokeToken(tokenB64Hash string) (userId int, err error) {
	// starting db transaction to first update ( handle error ) and then get id that we updated ( handle error from it )
	tx, err := r.db.Begin()
	if err != nil {
		return 0, toRepoError(err)
	}
	// defering to rollback transation to rollback if transation didn't commit
	defer func() {
		tx.Rollback()
	}()

	res, err := tx.Exec(`
	UPDATE refresh_tokens
	SET revoked_at = NOW()
	WHERE token_b64_hash = $1 AND revoked_at IS NULL
	`, tokenB64Hash)

	if err != nil {
		return 0, toRepoError(err)
	}

	if rowsAffected, err := res.RowsAffected(); err != nil {
		return 0, toRepoError(err)
	} else if rowsAffected == 0 {
		return 0, repo.ErrNothingChanged
	}

	row := tx.QueryRow(`
		SELECT user_id
		FROM refresh_tokens
		WHERE token_b64_hash = $1
	`, tokenB64Hash)

	if err := row.Scan(&userId); err != nil {
		return 0, toRepoError(err)
	}

	// end of transation
	if err := tx.Commit(); err != nil {
		return 0, toRepoError(err)
	}

	return userId, nil
}

func (r *PgRepository) CheckToken(tokenB64Hash string) (userId int, err error) {
	row := r.db.QueryRow(`
	SELECT user_id from refresh_tokens
	WHERE token_b64_hash = $1
	AND revoked_at IS NULL
	AND expires_at > NOW();
	`, tokenB64Hash)

	if err := row.Scan(&userId); err != nil {
		return 0, toRepoError(err)
	}

	return userId, nil
}

// func (r *PgRepository) RevokeAllFromUser(userID int) error
