package store

import (
	"context"
	"embed"

	godb "github.com/paaavkata/go-db"
)

//go:embed sql/*.sql
var sqlFiles embed.FS

// DBService wraps godb.DBService and adds Migrate() for target-service.
type DBService struct {
	*godb.DBService
}

// NewDBService opens a pgxpool connection using the provided URI.
func NewDBService(dbUri string) (*DBService, error) {
	db, err := godb.NewDBService(dbUri, nil)
	if err != nil {
		return nil, err
	}
	return &DBService{DBService: db}, nil
}

// Migrate applies every SQL file in internal/store/sql/ in alphabetical order.
// Every statement must be idempotent (CREATE TABLE IF NOT EXISTS, etc.).
func (s *DBService) Migrate() error {
	entries, err := sqlFiles.ReadDir("sql")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		sql, err := sqlFiles.ReadFile("sql/" + entry.Name())
		if err != nil {
			return err
		}
		if _, err := s.Pool().Exec(context.Background(), string(sql)); err != nil {
			return err
		}
	}
	return nil
}
