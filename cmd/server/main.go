package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"todo-auth/internal/handlers"
	"todo-auth/pkg/db"
	"todo-auth/pkg/logger"
	pb "todo-auth/proto"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

	// http.HandleFunc("/verify", handlers.VerifyToken)
	http.HandleFunc("/register", handlers.Register)
	http.HandleFunc("/login", handlers.Login)

	// Загружаем сертификат и ключ
	cert, err := tls.LoadX509KeyPair("certs/cert.pem", "certs/key.pem")
	if err != nil {
		panic(fmt.Sprintf("ошибка загрузки сертификатов: %v", err))
	}

	// Настраиваем TLS
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Минимальная версия TLS
	})

	// Создаём gRPC-сервер с TLS
	lis, err := net.Listen("tcp", ":8081")
	if err != nil {
		panic(fmt.Sprintf("не удалось запустить сервер: %v", err))
	}

	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAuthServiceServer(s, &handlers.AuthServer{})

	fmt.Println("gRPC Auth Service запущен на :8081 с TLS")
	if err := s.Serve(lis); err != nil {
		panic(fmt.Sprintf("ошибка запуска gRPC-сервера: %v", err))
	}

}
