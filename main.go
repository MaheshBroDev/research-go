package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

var db *sql.DB

// User structure
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// Item structure
type Item struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Database connection
func init() {
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPass, dbHost, dbPort, dbName)

	var err error
	db, err = sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
}

// Log performance metrics to CSV
// logPerformanceMetrics logs the performance metrics to a CSV file
func logPerformanceMetrics(start time.Time, endpoint string) {
	elapsed := time.Since(start)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	file, err := os.OpenFile("performance_metrics_go.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Error opening CSV file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Check if file is empty to write headers
	fileInfo, err := file.Stat()
	if err != nil {
		log.Println("Error getting file info:", err)
		return
	}
	if fileInfo.Size() == 0 {
		headers := []string{"Timestamp", "Endpoint", "Allocated Memory (bytes)", "Total Allocated Memory (bytes)", "System Memory (bytes)", "Garbage Collections", "Elapsed Time", "CPU Usage (%)", "Memory Usage (KB)"}
		if err := writer.Write(headers); err != nil {
			log.Println("Error writing headers to CSV file:", err)
			return
		}
	}

	// Capture CPU and Memory usage
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		log.Println("Error getting CPU usage:", err)
		return
	}
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		log.Println("Error getting memory usage:", err)
		return
	}

	record := []string{
		time.Now().Format(time.RFC3339),
		endpoint,
		fmt.Sprintf("%d", m.Alloc),
		fmt.Sprintf("%d", m.TotalAlloc),
		fmt.Sprintf("%d", m.Sys),
		fmt.Sprintf("%d", m.NumGC),
		elapsed.String(),
		fmt.Sprintf("%.2f", cpuPercent[0]),
		fmt.Sprintf("%.2f", float64(memInfo.Used)/1024),
	}

	if err := writer.Write(record); err != nil {
		log.Println("Error writing to CSV file:", err)
	}
}

// Middleware to log performance metrics
func performanceLoggingMiddleware(next http.HandlerFunc, endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		logPerformanceMetrics(start, endpoint)
	}
}

// Authentication Middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("Authorization")
		if len(apiKey) < 7 || apiKey[:7] != "Bearer " {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := apiKey[7:]
		var user User
		err := db.QueryRow("SELECT username FROM users WHERE token = ?", token).Scan(&user.Username)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Login Endpoint
func login(w http.ResponseWriter, r *http.Request) {
	var credentials User
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var storedToken string
	err = db.QueryRow("SELECT token FROM users WHERE username = ? AND password = ?", credentials.Username, credentials.Password).
		Scan(&storedToken)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	response := map[string]string{"token": storedToken}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get Items (Authenticated)
func getItems(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, value FROM items")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []Item
	for rows.Next() {
		var item Item
		rows.Scan(&item.ID, &item.Name, &item.Value)
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// Create Item (Authenticated)
func createItem(w http.ResponseWriter, r *http.Request) {
	var newItem Item
	err := json.NewDecoder(r.Body).Decode(&newItem)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO items (name, value) VALUES (?, ?)", newItem.Name, newItem.Value)
	if err != nil {
		http.Error(w, "Error saving item", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, "Item created")
}

// Get Single Item (Authenticated)
func getSingleItem(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid id parameter type, Must be a number", http.StatusBadRequest)
		return
	}

	var item Item
	err = db.QueryRow("SELECT id, name, value FROM items WHERE id = ?", id).Scan(&item.ID, &item.Name, &item.Value)
	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

// Get last item from the database
func getLastItem(w http.ResponseWriter, r *http.Request) {
	var item Item
	err := db.QueryRow("SELECT id, name, value FROM items ORDER BY id DESC LIMIT 1").Scan(&item.ID, &item.Name, &item.Value)
	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

// Get test loop metrics
func loopCheck(w http.ResponseWriter, r *http.Request) {

	loopCountStr := r.URL.Query().Get("loopcount")
	if loopCountStr == "" {
		http.Error(w, "Missing loopcount parameter", http.StatusBadRequest)
		return
	}

	loopCount, err := strconv.Atoi(loopCountStr)
	if err != nil {
		http.Error(w, "Invalid loopcount parameter", http.StatusBadRequest)
		return
	}

	for i := 0; i < loopCount; i++ {
		i++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// Get metrics csv file
func getMetrics(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat("performance_metrics_go.csv"); os.IsNotExist(err) {
		http.Error(w, "Metrics file not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, "performance_metrics_go.csv")
}

func main() {
	http.HandleFunc("/login", performanceLoggingMiddleware(login, "/login"))
	http.HandleFunc("/items", authMiddleware(performanceLoggingMiddleware(getItems, "/items")))
	http.HandleFunc("/item", authMiddleware(performanceLoggingMiddleware(getSingleItem, "/item")))
	http.HandleFunc("/item/last", authMiddleware(performanceLoggingMiddleware(getLastItem, "/item/last")))
	http.HandleFunc("/items/create", authMiddleware(performanceLoggingMiddleware(createItem, "/items/create")))
	http.HandleFunc("/test/loop", authMiddleware(performanceLoggingMiddleware(loopCheck, "/test/loop")))

	http.HandleFunc("/metrics", performanceLoggingMiddleware(getMetrics, "/metrics"))

	log.Println("Starting API server on port 8080...")
	http.ListenAndServe(":8080", nil)
}
