package repository

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Mini-Project-MDP/sso-service/pkg/domain"
	"github.com/joho/godotenv"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func InitDB(dbPath string) (*gorm.DB, error) {
	_ = godotenv.Load()

	tursoURL := os.Getenv("TURSO_DATABASE_URL")
	tursoToken := os.Getenv("TURSO_AUTH_TOKEN")

	var db *gorm.DB
	var err error

	if strings.HasPrefix(tursoURL, "libsql://") || strings.HasPrefix(tursoURL, "https://") {
		dsn := fmt.Sprintf("%s?authToken=%s", tursoURL, tursoToken)
		log.Printf("Connecting to Turso libSQL Cloud Database (%s)...\n", tursoURL)
		db, err = gorm.Open(sqlite.New(sqlite.Config{
			DriverName: "libsql",
			DSN:        dsn,
		}), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	} else {
		if dbPath == "" {
			dbPath = "sso.db"
		}
		log.Printf("Connecting to Local SQLite Database (%s)...\n", dbPath)
		db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	log.Println("Migrating database schemas...")
	err = db.AutoMigrate(
		&domain.ClientApp{},
		&domain.SSOUser{},
		&domain.UserAppMapping{},
		&domain.SSOSession{},
		&domain.AuthCode{},
		&domain.AuditLog{},
	)
	if err != nil {
		return nil, fmt.Errorf("auto-migration error: %w", err)
	}

	log.Println("Seeding initial SSO dataset...")
	if err := SeedData(db); err != nil {
		log.Printf("Warning: Seeding failed or already seeded: %v\n", err)
	}

	return db, nil
}
