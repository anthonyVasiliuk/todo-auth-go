package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"todo-auth/internal/models"
	"todo-auth/pkg/db"
	jwtsecret "todo-auth/pkg/jwt"
	pb "todo-auth/proto" // Импорт сгенерированного пакета

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret = []byte(jwtsecret.GetJWTSecret()) // Секретный ключ для JWT (в продакшене храните в переменных окружения)
	validate  = validator.New()
)

// AuthServer реализует интерфейс AuthServiceServer из auth_grpc.pb.go
type AuthServer struct {
	pb.UnimplementedAuthServiceServer // Встраиваем для совместимости
}

func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Некорректный запрос", http.StatusBadRequest)
		return
	}

	if err := validate.Struct(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Ошибка хеширования пароля", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	if err := db.DB.Create(&user).Error; err != nil {
		http.Error(w, "Ошибка создания пользователя", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Некорректный запрос", http.StatusBadRequest)
		return
	}

	var user models.User
	if err := db.DB.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		http.Error(w, "Неверный пароль", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// VerifyToken реализует метод gRPC
func (s *AuthServer) VerifyToken(ctx context.Context, req *pb.TokenRequest) (*pb.TokenResponse, error) {
	tokenStr := req.GetToken()
	if tokenStr == "" {
		return nil, fmt.Errorf("токен не предоставлен")
	}

	fmt.Printf("Получен токен: %s\n", tokenStr) // Логирование для отладки

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неверный метод подписи")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("неверный токен: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("неверные данные токена")
	}

	userID, _ := claims["user_id"].(float64)
	role, _ := claims["role"].(string)

	return &pb.TokenResponse{
		UserId: int32(userID),
		Role:   role,
	}, nil
}
