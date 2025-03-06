package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
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

// DockerStats struct to hold docker metrics
type DockerStats struct {
	Timestamp         string  `json:"timestamp"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemoryUsage       float64 `json:"memory_usage"`
	ActiveConnections float64 `json:"active_connections"`
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

	file, err := os.OpenFile("performance_metrics_go.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Error opening JSON file:", err)
		return
	}
	defer file.Close()

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

	record := map[string]interface{}{
		"Timestamp":            time.Now().Format(time.RFC3339),
		"Endpoint":             endpoint,
		"AllocatedMemory":      m.Alloc,
		"TotalAllocatedMemory": m.TotalAlloc,
		"SystemMemory":         m.Sys,
		"GarbageCollections":   m.NumGC,
		"ElapsedTime":          elapsed.String(),
		"CPUUsage":             cpuPercent[0],
		"MemoryUsageKB":        float64(memInfo.Used) / 1024,
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(record); err != nil {
		log.Println("Error writing to JSON file:", err)
	}
}

// Function to log Docker stats
func logDockerStats() {
	ticker := time.NewTicker(5 * time.Second) // Collect stats every 5 seconds
	quit := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				timestamp := time.Now().Format(time.RFC3339)

				// Get CPU usage
				cpuPercent, err := cpu.Percent(0, false)
				if err != nil {
					log.Println("Error getting CPU usage:", err)
					continue
				}

				// Get memory usage
				memInfo, err := mem.VirtualMemory()
				if err != nil {
					log.Println("Error getting memory usage:", err)
					continue
				}

				// Get active connections (example: total bytes sent)
				// netIO, err := net.IOCounters(false)
				// if err != nil {
				// 	log.Println("Error getting network I/O:", err)
				// 	continue
				// }
				// activeConnections := float64(netIO[0].BytesSent)

				dockerStats := DockerStats{
					Timestamp:         timestamp,
					CPUUsage:          cpuPercent[0],
					MemoryUsage:       float64(memInfo.Used) / float64(memInfo.Total) * 100, // Memory usage in percentage
					ActiveConnections: 0,
				}

				file, err := os.OpenFile("docker_metrics_go.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Println("Error opening docker_metrics_go.json:", err)
					continue
				}
				defer file.Close()

				encoder := json.NewEncoder(file)
				if err := encoder.Encode(dockerStats); err != nil {
					log.Println("Error writing to docker_metrics_go.json:", err)
				}

			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
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
	if _, err := os.Stat("performance_metrics_go.json"); os.IsNotExist(err) {
		http.Error(w, "Metrics file not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, "performance_metrics_go.json")
}

// Get docker metrics json file
func getDockerMetrics(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat("docker_metrics_go.json"); os.IsNotExist(err) {
		http.Error(w, "Docker metrics file not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, "docker_metrics_go.json")
}

type SortResult struct {
	Algorithm   string        `json:"algorithm"`
	ElapsedTime time.Duration `json:"elapsed_time"`
	SortedList  []int         `json:"sorted_list"`
	CPUPercent  float64       `json:"cpu_percent"`
	MemoryUsage float64       `json:"memory_usage_kb"`
}

func bubbleSort(list []int) ([]int, time.Duration) {
	start := time.Now()
	n := len(list)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if list[j] > list[j+1] {
				list[j], list[j+1] = list[j+1], list[j]
			}
		}
	}
	elapsed := time.Since(start)
	return list, elapsed
}

func quickSort(list []int) ([]int, time.Duration) {
	start := time.Now()
	quickSortHelper(list, 0, len(list)-1)
	elapsed := time.Since(start)
	return list, elapsed
}

func quickSortHelper(list []int, low, high int) {
	if low < high {
		partitionIndex := partition(list, low, high)

		quickSortHelper(list, low, partitionIndex-1)
		quickSortHelper(list, partitionIndex+1, high)
	}
}

func partition(list []int, low, high int) int {
	pivot := list[high]
	i := low - 1

	for j := low; j < high; j++ {
		if list[j] < pivot {
			i++
			list[i], list[j] = list[j], list[i]
		}
	}
	list[i+1], list[high] = list[high], list[i+1]
	return i + 1
}

// Note: Binary Sort is typically used to describe inserting elements into an already sorted list
// This implementation will sort the whole list using binary insertion
func binarySort(list []int) ([]int, time.Duration) {
	start := time.Now()
	for i := 1; i < len(list); i++ {
		key := list[i]
		left := 0
		right := i - 1

		// Find the correct position to insert the key using binary search
		for left <= right {
			mid := left + (right-left)/2
			if key < list[mid] {
				right = mid - 1
			} else {
				left = mid + 1
			}
		}

		// Shift elements to make space for the key
		for j := i - 1; j >= left; j-- {
			list[j+1] = list[j]
		}

		// Insert the key at the correct position
		list[left] = key
	}

	elapsed := time.Since(start)
	return list, elapsed
}

func sortHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input struct {
		List []int `json:"list"`
	}

	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	list := input.List

	// Perform sorts and capture metrics
	bubbleSorted, bubbleTime, bubbleCPU, bubbleMem := sortWithMetrics(bubbleSort, copyList(list))
	quickSorted, quickTime, quickCPU, quickMem := sortWithMetrics(quickSort, copyList(list))
	binarySorted, binaryTime, binaryCPU, binaryMem := sortWithMetrics(binarySort, copyList(list))

	results := []SortResult{
		{Algorithm: "Bubble Sort", ElapsedTime: bubbleTime, SortedList: bubbleSorted, CPUPercent: bubbleCPU, MemoryUsage: bubbleMem},
		{Algorithm: "Quick Sort", ElapsedTime: quickTime, SortedList: quickSorted, CPUPercent: quickCPU, MemoryUsage: quickMem},
		{Algorithm: "Binary Sort", ElapsedTime: binaryTime, SortedList: binarySorted, CPUPercent: binaryCPU, MemoryUsage: binaryMem},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

type sortFunc func([]int) ([]int, time.Duration)

func sortWithMetrics(sortFunc sortFunc, list []int) ([]int, time.Duration, float64, float64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memBefore := float64(m.Alloc)

	cpuPercentChan := make(chan []float64, 1)
	go func() {
		cpuPercent, _ := cpu.Percent(0, false)
		cpuPercentChan <- cpuPercent
	}()

	sortedList, elapsedTime := sortFunc(list)

	cpuPercent := <-cpuPercentChan
	cpuUsage := cpuPercent[0]

	runtime.ReadMemStats(&m)
	memAfter := float64(m.Alloc)
	memoryUsage := float64(memAfter-memBefore) / 1024

	return sortedList, elapsedTime, cpuUsage, memoryUsage
}

// Helper function to copy a list
func copyList(list []int) []int {
	newList := make([]int, len(list))
	copy(newList, list)
	return newList
}

func loaderioHandler(w http.ResponseWriter, r *http.Request) {
	re := regexp.MustCompile(`^/loaderio-([a-zA-Z0-9]{32})\.txt$`)
	matches := re.FindStringSubmatch(r.URL.Path)
	if len(matches) != 2 {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	filename := matches[1]
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "loaderio-%s", filename)
}

// Update Item (Authenticated)
func updateItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	var updatedItem Item
	err = json.NewDecoder(r.Body).Decode(&updatedItem)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE items SET name = ?, value = ? WHERE id = ?", updatedItem.Name, updatedItem.Value, id)
	if err != nil {
		http.Error(w, "Error updating item", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Item updated")
}

// Delete Item (Authenticated)
func deleteItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	_, err = db.Exec("DELETE FROM items WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error deleting item", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Item deleted")
}

// Delete Last Item (Authenticated)
func deleteLastItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var id int
	err := db.QueryRow("SELECT id FROM items ORDER BY id DESC LIMIT 1").Scan(&id)
	if err != nil {
		http.Error(w, "No items found", http.StatusNotFound)
		return
	}

	_, err = db.Exec("DELETE FROM items WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error deleting last item", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Last item deleted")
}

func main() {
	logDockerStats()
	http.HandleFunc("/login", performanceLoggingMiddleware(login, "/login"))
	http.HandleFunc("/items", authMiddleware(performanceLoggingMiddleware(getItems, "/items")))
	http.HandleFunc("/item", authMiddleware(performanceLoggingMiddleware(getSingleItem, "/item")))
	http.HandleFunc("/item/last", authMiddleware(performanceLoggingMiddleware(getLastItem, "/item/last")))
	http.HandleFunc("/items/create", authMiddleware(performanceLoggingMiddleware(createItem, "/items/create")))
	http.HandleFunc("/test/loop", authMiddleware(performanceLoggingMiddleware(loopCheck, "/test/loop")))

	http.HandleFunc("/metrics", performanceLoggingMiddleware(getMetrics, "/metrics"))
	http.HandleFunc("/docker_metrics", getDockerMetrics)
	http.HandleFunc("/sort", authMiddleware(performanceLoggingMiddleware(sortHandler, "/sort")))

	http.HandleFunc("/item/update", authMiddleware(performanceLoggingMiddleware(updateItem, "/item/update")))
	http.HandleFunc("/item/delete", authMiddleware(performanceLoggingMiddleware(deleteItem, "/item/delete")))
	http.HandleFunc("/item/last/delete", authMiddleware(performanceLoggingMiddleware(deleteLastItem, "/item/last/delete")))

	http.HandleFunc("/loaderio-", loaderioHandler)
	http.HandleFunc("/loaderio-ec6d3c2803480d0d7a8cd4d1d95ece88.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "loaderio-ec6d3c2803480d0d7a8cd4d1d95ece88")
	})
	log.Println("Starting API server on port 8080...")
	http.ListenAndServe(":8080", nil)
}
