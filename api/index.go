package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	deliveryHttp "github.com/Mini-Project-MDP/sso-service/pkg/delivery/http"
	"github.com/Mini-Project-MDP/sso-service/pkg/repository"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"gorm.io/gorm"
)

var (
	mu          sync.Mutex
	initialized bool
	httpHandler http.HandlerFunc
	initErr     error
	db          *gorm.DB
)

func initialize() error {
	tmpDbPath := filepath.Join(os.TempDir(), "sso.db")
	databaseConnection, err := repository.InitDB(tmpDbPath)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	db = databaseConnection

	app := fiber.New(fiber.Config{
		AppName: "Mayora SSO Identity Service v1.0",
	})

	deliveryHttp.SetupRouter(app, db)

	httpHandler = adaptor.FiberApp(app)
	return nil
}

// Handler is the serverless entrypoint for Vercel deployments.
func Handler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	if !initialized {
		initErr = initialize()
		if initErr == nil {
			initialized = true
		}
	}
	err := initErr
	h := httpHandler
	mu.Unlock()

	if err != nil {
		log.Printf("Vercel handler init error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":false,"error":"Initialization error: %v"}`+"\n", err)
		return
	}

	h(w, r)
}
