package godb

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fgiamma/gocommons/gohttp"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const MYSQLAPP = 0
const POSTGRESQLAPP = 1

type CheckResult struct {
	Key         string `json:"key"`
	ReturnValue bool   `json:"return_value"`
}

type Check struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CheckArray struct {
	Checks []Check `json:"checks"`
	Uid    string  `json:"uid"`
}

type LogWriter struct {
}

func (writer LogWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().Format("2006-01-02 15:04:05") + " " + string(bytes))
}

type ConfigData struct {
	Title    string
	Http     HttpData     `toml:"http"`
	Database DatabaseData `toml:"database"`
	Folders  FoldersData  `toml:"folders"`
}

type FoldersData struct {
	RootFolder   string `rootfolder:"http"`
	SharedFolder string `toml:"sharedfolder"`
}

type Database struct {
	Host           string `json:"host"`
	Port           string `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	DatabaseName   string `json:"dbname"`
	Ssl            bool   `json:"ssl"`
	SslCertificate string `json:"ssl_certificate"`
}

type Config struct {
	Logfile     string   `json:"logfile"`
	Database    Database `json:"database"`
	BaseDataUrl string   `json:"base_data_url"`
	ServerPort  int      `json:"server_port"`
}

type DatabaseData struct {
	Username string
	Password string
	Server   string
	Port     int
	Dbname   string
}

type HttpData struct {
	Port  int `toml:"port"`
	Port2 int `toml:"port2"`
	Ssl   int `toml:"ssl"`
}

type JSONB map[string]interface{}

// Value Marshal
func (jsonField JSONB) Value() (driver.Value, error) {
	return json.Marshal(jsonField)
}

// Scan Unmarshal
func (jsonField *JSONB) Scan(value interface{}) error {
	data, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(data, &jsonField)
}

func ReadConfig[T any](fileName string, conf T) (T, error) {
	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
		return conf, err
	}

	// var conf ConfigData
	err = toml.Unmarshal(content, &conf)

	if err != nil {
		log.Fatal(err)
		return conf, err
	}

	return conf, nil
}

func InitData(configFolder string) (ConfigData, *gorm.DB, *sql.DB, error) {
	var conf ConfigData
	conf, err := ReadConfig(configFolder+"config.toml", conf)

	if err != nil {
		return ConfigData{}, nil, nil, err
	}

	// Create database pool
	dbPort := strconv.Itoa(conf.Database.Port)
	dsn := conf.Database.Username + ":" + conf.Database.Password + "@tcp(" + conf.Database.Server + ":" + dbPort + ")/" + conf.Database.Dbname + "?charset=utf8mb4&parseTime=True&loc=Local"

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,  // Slow SQL threshold
			LogLevel:                  logger.Error, // Log level
			IgnoreRecordNotFoundError: true,         // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,        // Disable color
		},
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		return ConfigData{}, nil, nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return ConfigData{}, nil, nil, err
	}

	if err = sqlDB.Ping(); err != nil {
		return ConfigData{}, nil, nil, err
	}

	return conf, db, sqlDB, nil
}

func InitPostgresData(configFolder string) (ConfigData, *gorm.DB, *sql.DB, error) {
	var conf ConfigData
	conf, err := ReadConfig(configFolder+"config.toml", conf)

	if err != nil {
		return ConfigData{}, nil, nil, err
	}

	// Create database pool
	dbPort := strconv.Itoa(conf.Database.Port)
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Europe/Rome", conf.Database.Server, conf.Database.Username, conf.Database.Password, conf.Database.Dbname, dbPort)

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,  // Slow SQL threshold
			LogLevel:                  logger.Error, // Log level
			IgnoreRecordNotFoundError: true,         // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,        // Disable color
		},
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		return ConfigData{}, nil, nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return ConfigData{}, nil, nil, err
	}

	if err = sqlDB.Ping(); err != nil {
		return ConfigData{}, nil, nil, err
	}

	return conf, db, sqlDB, nil
}

func ConfigApp(mode int) (*gorm.DB, *sql.DB, error) {
	log.SetFlags(log.Lshortfile)
	log.SetOutput(new(LogWriter))

	// Path of executable, first attempt
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	exPath = fmt.Sprintf("%s/", exPath)

	_, err = os.Stat(exPath + "/config.toml")

	var configFolder *string
	// No path has been found, select default
	if err != nil {
		configFolder = flag.String("configfolder", "./", "Configuration folder TOML file")
		flag.Parse()
	} else {
		configFolder = &exPath
	}

	var db *gorm.DB
	var sqlDB *sql.DB

	if mode == 0 {
		_, db, sqlDB, err = InitData(*configFolder)

	} else {
		_, db, sqlDB, err = InitPostgresData(*configFolder)
	}

	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	// defer sqlDB.Close()

	return db, sqlDB, nil
}

func GetDbParameter(db *gorm.DB, parameterName string) string {
	var parameterValue string
	sql := "SELECT parameter_value FROM parameters WHERE parameter_name=?;"
	db.Raw(sql, parameterName).Scan(&parameterValue)

	return parameterValue
}

func GetIntDbParameter(db *gorm.DB, parameterName string) int {
	var parameterValueString sql.NullString
	sql := `SELECT parameter_value FROM parameters WHERE parameter_name=?;`
	db.Raw(sql, parameterName).Scan(&parameterValueString)

	parameterValue, err := strconv.Atoi(parameterValueString.String)
	if err != nil {
		return 0
	}

	return parameterValue
}

func CheckMultipleValues(db *gorm.DB, tableName string, w http.ResponseWriter, r *http.Request) {
	var checks CheckArray
	err := json.NewDecoder(r.Body).Decode(&checks)
	if err != nil {
		gohttp.WriteInvalidResponse(w, "ko", "Error decoding params")
		return
	}

	var extraSql string = ""
	if checks.Uid != "" {
		extraSql = " AND uniqueid <> '" + checks.Uid + "'"
	}

	checkResults := make([]CheckResult, 0)

	for i := 0; i < len(checks.Checks); i++ {
		item := checks.Checks[i]
		if item.Key == "" || item.Value == "" {
			gohttp.WriteInvalidResponse(w, "ko", "Error evaluating items")
			return
		}

		sql := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s=?%s;", tableName, item.Key, extraSql)

		// sql := "SELECT COUNT(*) FROM " + tableName + " WHERE " + item.Key + "='" + item.Value + "'" + extraSql + ";"
		var counter int
		db.Raw(sql, item.Value).Scan(&counter)

		var returnValue bool = true
		if counter > 0 {
			returnValue = false
		}

		var checkResult *CheckResult = new(CheckResult)
		checkResult.Key = item.Key
		checkResult.ReturnValue = returnValue

		checkResults = append(checkResults, *checkResult)
	}

	returnObject := make(map[string]interface{})
	returnObject["element"] = checkResults

	gohttp.WriteValidResponse(w, "ok", returnObject)
}
