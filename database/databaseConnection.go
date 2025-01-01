package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
	"github.com/ojeniweh10/task-manager-user-service/config"
)

var (
	host     = config.Db().Host
	user     = config.Db().User
	password = config.Db().Password
	dbname   = config.Db().Name
)

// NewConnection initializes a connection to the MySQL database
func NewConnection() *sql.DB {
	databaseUrl := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", user, password, host, dbname)
	db, err := sql.Open("mysql", databaseUrl)
	if err != nil {
		log.Fatalf("Error connecting to database: %v\n", err)
	}

	// Verifying the connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging database: %v\n", err)
	}

	fmt.Println("Successfully connected to database!")
	return db
}

// Insert function to insert a record into a specified table in the MySQL database
func Insert(db *sql.DB, table string, data map[string]interface{}) error {
	var columns, placeholders string
	var values []interface{}
	i := 1
	for k, v := range data {
		if i > 1 {
			columns += ", "
			placeholders += ", "
		}
		columns += k
		placeholders += "?"
		values = append(values, v)
		i++
	}
	sqlQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, columns, placeholders)
	_, err := db.Exec(sqlQuery, values...)
	if err != nil {
		return fmt.Errorf("error executing insert query: %v", err)
	}

	return nil
}

// Update function to update a record in the specified table in the MySQL database
func Update(db *sql.DB, table string, data map[string]interface{}, condition map[string]interface{}) error {
	var setClause string
	var values []interface{}
	i := 1
	for k, v := range data {
		if i > 1 {
			setClause += ", "
		}
		setClause += fmt.Sprintf("%s = ?", k)
		values = append(values, v)
		i++
	}

	var whereClause string
	for k, v := range condition {
		if whereClause == "" {
			whereClause = " WHERE "
		} else {
			whereClause += " AND "
		}
		whereClause += fmt.Sprintf("%s = ?", k)
		values = append(values, v)
	}

	sqlQuery := fmt.Sprintf("UPDATE %s SET %s%s", table, setClause, whereClause)
	_, err := db.Exec(sqlQuery, values...)
	if err != nil {
		return fmt.Errorf("error executing update query: %v", err)
	}

	return nil
}
