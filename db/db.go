package db

import (
	"fmt"
	"os"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
)

var db *gorm.DB

func init() {

	e := godotenv.Load()
	if e != nil {
		fmt.Print(e)
	}

	databaseUrl := os.Getenv("database_url")

	if databaseUrl == "" {
		panic("database url is empty")
	}

	conn, err := gorm.Open("postgres", databaseUrl)
	if err != nil {
		fmt.Print(err)
	}

	db = conn
}

func GetDB() *gorm.DB {
	return db
}
