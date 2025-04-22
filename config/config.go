package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// AppConfig holds all configuration settings
type AppConfig struct {
	ServiceName string
	DatabaseURL string
	DBPassword  string
	JWTSecret   string
	ServerPort  string
	DebugMode   bool
}

var Config *AppConfig

// LoadConfig reads environment variables and initializes Config
func LoadConfig() {
	// Load .env file (if exists)
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using system environment variables")
	}

	// Get values from environment variables
	dbPassword := os.Getenv("DB_PASSWORD")
	databaseURL := os.Getenv("DATABASE_URL")

	// Replace placeholder with actual DB password if present
	if dbPassword != "" {
		databaseURL = strings.ReplaceAll(databaseURL, "${DB_PASSWORD}", dbPassword)
	}

	debugMode, err := strconv.ParseBool(getEnv("DEBUG_MODE", "false"))
	if err != nil {
		log.Println("Warning: Invalid value for DEBUG_MODE, defaulting to false")
		debugMode = false
	}

	Config = &AppConfig{
		ServiceName: getEnv("SERVICE_NAME", "Authentication"),
		DatabaseURL: databaseURL,
		DBPassword:  dbPassword, // ✅ Store separately
		JWTSecret:   getEnv("JWT_SECRET", ""),
		ServerPort:  getEnv("PORT", "8080"),
		DebugMode:   debugMode,
	}

	// Ensure required values exist
	if Config.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required but missing")
	}
	if Config.JWTSecret == "" {
		log.Fatal("JWT_SECRET is required but missing")
	}

	log.Println("✅ Configuration loaded successfully")
}

// getEnv fetches environment variables with a default fallback
func getEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}
