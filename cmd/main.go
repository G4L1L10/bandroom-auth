package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/g4l1l10/bandroom/authentication/middlewares"
	"github.com/g4l1l10/bandroom/authentication/routes"

	"github.com/g4l1l10/bandroom/authentication/db"

	"github.com/g4l1l10/bandroom/authentication/config"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	config.LoadConfig()

	// Connect to the database
	db.ConnectDatabase()
	defer db.CloseDatabase()

	// Initialize Gin router
	router := gin.Default()

	// Apply middlewares
	router.Use(middlewares.CORSMiddleware()) // Enable CORS
	router.Use(gin.Recovery())               // Recover from panics

	// Register authentication routes
	routes.AuthRoutes(router)
	routes.StatusRoutes(router)

	// Graceful shutdown handling
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Ensure Cloud Run compatibility: Use $PORT from environment variables
	serverPort := os.Getenv("PORT")
	if serverPort == "" {
		serverPort = "8081" // Default port if not set
	}

	// Start server in a goroutine
	go func() {
		log.Println("🚀 Server is running on port:", serverPort)
		if err := router.Run(":" + serverPort); err != nil {
			log.Fatalf("❌ Failed to start server: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-quit
	log.Println("🛑 Shutting down server gracefully...")
}
