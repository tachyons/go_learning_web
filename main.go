package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"
)

type User struct {
	gorm.Model
	Name           string
	Email          string `gorm:"type:varchar(100);unique_index"`
	HashedPassword string
}

type Credentials struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type SignupParams struct {
	Password string `json:"password"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

func hashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Hello")
	fmt.Fprintln(w, "Hello")
}
func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
func CreateToken(user User) (string, error) {
	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "to_be_updated") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = user.ID
	atClaims["email"] = user.Email
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := gorm.Open("sqlite3", "test.db")

	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// If there is something wrong with the request body, return a 400 status
		fmt.Println("Failed", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var user User
	db.First(&user, "email= ?", creds.Email)
	if comparePasswords(user.HashedPassword, []byte(creds.Password)) {
		token, err := CreateToken(user)
		fmt.Println(token, err)
		fmt.Fprintln(w, token)
	} else {
		fmt.Println("Failed")
	}
	if err != nil {
		// If there is an issue with the database, return a 500 error
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := gorm.Open("sqlite3", "test.db")
	fmt.Println("Signup")

	params := &SignupParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		fmt.Println("Failed")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user := User{Name: params.Name, Email: params.Email, HashedPassword: hashAndSalt([]byte(params.Password))}
	db.NewRecord(user)
	db.Create(&user)
}

func SetupDatabase() {

	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	// Migrate the schema
	db.AutoMigrate(&User{})
}

func main() {
	SetupDatabase()
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler).Methods("POST")
	r.HandleFunc("/signup", SignupHandler).Methods("POST")
	http.Handle("/", r)
	http.ListenAndServe(":8081", r)
}
