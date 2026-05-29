package auth

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("ebpf-sentinel-secret-change-me")

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type AuthManager struct {
	db *sql.DB
}

func NewAuthManager(dbPath string) (*AuthManager, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT DEFAULT 'viewer'
	)`)
	if err != nil {
		return nil, err
	}

	am := &AuthManager{db: db}
	am.CreateUser("admin", "admin123", "admin")
	am.CreateUser("operator", "operator123", "operator")

	return am, nil
}

func (am *AuthManager) CreateUser(username, password, role string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = am.db.Exec("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
		username, string(hash), role)
	return err
}

func (am *AuthManager) VerifyPassword(username, password string) (*User, error) {
	var user User
	var hash string
	err := am.db.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?",
		username).Scan(&user.ID, &user.Username, &hash, &user.Role)
	if err != nil {
		return nil, fmt.Errorf("用户不存在")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, fmt.Errorf("密码错误")
	}
	return &user, nil
}

func (am *AuthManager) GenerateToken(user *User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString(jwtSecret)
}

func (am *AuthManager) ValidateToken(tokenStr string) (*User, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token无效")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("token解析失败")
	}
	return &User{
		ID:       int(claims["user_id"].(float64)),
		Username: claims["username"].(string),
		Role:     claims["role"].(string),
	}, nil
}

func (am *AuthManager) ListUsers() ([]User, error) {
	rows, err := am.db.Query("SELECT id, username, role FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Role)
		users = append(users, u)
	}
	return users, nil
}

func (am *AuthManager) Close() {
	am.db.Close()
}
