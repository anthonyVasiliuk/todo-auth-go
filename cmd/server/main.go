package main

import (
	"fmt"
	"net/http"
	"todo-auth/internal/handlers"
	"todo-auth/pkg/db"
	"todo-auth/pkg/logger"

	"github.com/joho/godotenv"
)

func main() {
	if err := logger.InitLogger(); err != nil {
		panic(err)
	}

	err := godotenv.Load()
	if err != nil {
		logger.Log.Infof("Error loading .env file")
	}

	if err := db.InitDB(); err != nil {
		panic(err)
	}
	
	http.HandleFunc("/verify", handlers.VerifyToken)
	http.HandleFunc("/register", handlers.Register)
	http.HandleFunc("/login", handlers.Login)

	fmt.Println("Auth Service запущен на :8081")
	http.ListenAndServe(":8081", nil)
}
