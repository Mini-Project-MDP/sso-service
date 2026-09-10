package main

import (
	"log"
	"os"

	"github.com/Mini-Project-MDP/sso-service/pkg/delivery/http"
	"github.com/Mini-Project-MDP/sso-service/pkg/repository"
	"github.com/gofiber/fiber/v3"
)

func main() {
	log.Println("Starting Mayora Single Sign-On (SSO) Service...")

	// Initialize DB
	db, err := repository.InitDB("sso.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	app := fiber.New(fiber.Config{
		AppName: "Mayora SSO Identity Service v1.0",
	})

	// Setup Routes
	http.SetupRouter(app, db)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082" // SSO Service runs on port 8081
	}

	log.Printf("Mayora SSO Service running on http://localhost:%s\n", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
}
