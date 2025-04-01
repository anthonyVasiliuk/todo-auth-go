package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"todo-auth/internal/models"
	"todo-auth/pkg/db"
	jwtsecret "todo-auth/pkg/jwt"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret = []byte(jwtsecret.GetJWTSecret()) // Секретный ключ для JWT (в продакшене храните в переменных окружения)
	validate  = validator.New()
)

func getJWTSecret() string {
	if os.Getenv("APP_ENV") != "production" {
		return os.Getenv("JWT_SECRET_TESTING")
	} else {
		return os.Getenv("JWT_SECRET")
	}
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

func VerifyToken(w http.ResponseWriter, r *http.Request) {
	// Читаем тело запроса как строку
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Ошибка чтения запроса", http.StatusBadRequest)
		return
	}
	tokenStr := string(body)
	if tokenStr == "" {
		http.Error(w, "Токен не предоставлен", http.StatusBadRequest)
		return
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неверный метод подписи")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Неверные данные токена", http.StatusUnauthorized)
		return
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		http.Error(w, "ID пользователя не найден в токене", http.StatusUnauthorized)
		return
	}
	role, ok := claims["role"].(string)
	if !ok {
		http.Error(w, "Роль не найдена в токене", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": int(userID),
		"role":    role,
	})
}
