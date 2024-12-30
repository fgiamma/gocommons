package database

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type ConfigData struct {
	Title    string
	Http     HttpData     `toml:"http"`
	Database DatabaseData `toml:"database"`
	Folders  FoldersData  `toml:"folders"`
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

type FoldersData struct {
	RootFolder   string `rootfolder:"http"`
	SharedFolder string `toml:"sharedfolder"`
}

type LogWriter struct {
}

func (writer LogWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().Format("2006-01-02 15:04:05") + " " + string(bytes))
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
