package gocommons

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"text/template"

	"crypto/md5"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"

	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"database/sql"
	"database/sql/driver"

	"github.com/BurntSushi/toml"
	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/oklog/ulid"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/datatypes"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	mysqlxx "github.com/go-sql-driver/mysql"
)

type ResponseObject struct {
	Code string      `json:"code"`
	Data interface{} `json:"data"`
}

type ListResponseObject struct {
	TotalRows   int         `json:"totalRows"`
	CurrentPage interface{} `json:"currentPage"`
}

type Check struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CheckArray struct {
	Checks []Check `json:"checks"`
	Uid    string  `json:"uid"`
}

type CheckResult struct {
	Key         string `json:"key"`
	ReturnValue bool   `json:"return_value"`
}

type ItemToBeDeleted struct {
	Uniqueid string `json:"uniqueid"`
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

type SessionListParameters struct {
	SortColumn string
	SortOrder  string
	Page       int
	PageSize   int
	ExtraData  map[string]interface{}
}

type SearchParams struct {
	Elements interface{} `json:"elements"`
}

var countryTz = map[string]string{
	"Rome": "Europe/Rome",
}

type S3Data struct {
	AwsAccessKeyId     string `json:"aws_access_key_id"`
	AwsSecretAccessKey string `json:"aws_secret_access_key"`
	AwsRegionName      string `json:"aws_region_name"`
	AwsBucketName      string `json:"aws_bucket_name"`
}

type DoS3Data struct {
	AccessKey  string `json:"access_key"`
	Secret     string `json:"secret"`
	Region     string `json:"region"`
	SpacesUrl  string `json:"spaces_url"`
	BucketName string `json:"bucket_name"`
}

type DatabaseData struct {
	Username string
	Password string
	Server   string
	Port     int
	Dbname   string
}

type HttpData struct {
	Port int
	Ssl  int `toml:"ssl"`
}

type FoldersData struct {
	RootFolder   string `rootfolder:"http"`
	SharedFolder string `toml:"sharedfolder"`
}
type ConfigData struct {
	Title    string
	Http     HttpData     `toml:"http"`
	Database DatabaseData `toml:"database"`
	Folders  FoldersData  `toml:"folders"`
}

type Locale struct {
	Id       int    `json:"id"`
	Lang     string `json:"lang"`
	Uniqueid string `json:"uniqueid"`
}

type LocaleString struct {
	Id              int            `json:"id"`
	ElementKey      string         `json:"element_key"`
	Annotations     string         `json:"annotations"`
	SystemGenerated bool           `json:"system_generated"`
	JsonData        datatypes.JSON `json:"json_data"`
	Uniqueid        string         `json:"uniqueid"`
}
type Translation struct {
	LangCode  string `json:"lang_code"`
	LangValue string `json:"lang_value"`
}

type LogWriter struct {
}

type CustomError struct {
	StatusCode int
	Err        string
}

func (qe *CustomError) Error() string {
	return qe.Err
}

func (qe *CustomError) GetCode() int {
	return qe.StatusCode
}

type TelegramMessage struct {
	ChatID int64  `json:"chat_id"`
	Text   string `json:"text"`
}

type Telegram struct {
	Url    string `json:"url"`
	ChatId int64  `json:"chat_id"`
}

func (t *Telegram) SetUrl(token string, chatId string) error {
	t.Url = fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	chatIdNumber, err := strconv.ParseInt(chatId, 10, 64)
	if err != nil {
		return err
	}

	t.ChatId = chatIdNumber
	return nil
}

// SendMessage sends a message to given URL.
func (t *Telegram) SendMessage(messageString string) error {
	message := TelegramMessage{
		ChatID: t.ChatId,
		Text:   messageString,
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	response, err := http.Post(t.Url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			log.Println("failed to close response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send successful request. Status was %q", response.Status)
	}
	return nil
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

var DateLayout string = "2006-01-02 15:04:05"
var CompactDateLayout string = "20060102150405"

var Dsn string

const MYSQLAPP = 0
const POSTGRESQLAPP = 1

func TimeIn(name string, utcTime time.Time) (time.Time, error) {
	loc, err := time.LoadLocation(countryTz[name])
	if err != nil {
		return time.Time{}, err
	}
	return utcTime.In(loc), nil
}

func GetUid() string {
	// Create new uniqueid
	uuidString := uuid.NewString()
	uuidString = strings.ToUpper(uuidString)
	uuidString = strings.Replace(uuidString, "-", "", -1)

	now := time.Now()
	nanoSeconds := now.UnixNano()

	hexValue := fmt.Sprintf("%x", nanoSeconds)
	hexValue = strings.ToUpper(hexValue)

	return hexValue + "-" + uuidString
}

func GetUidList(numberOfElements int) []string {
	uids := make([]string, numberOfElements)
	for i := 0; i < numberOfElements; i++ {
		uids[i] = GetUid()
	}

	return uids
}

func GetUlid() string {
	ulid := ulid.MustNew(ulid.Now(), cryptorand.Reader)
	return ulid.String()
}

func GetUlidList(numberOfElements int) []string {
	ulids := make([]string, numberOfElements)
	for i := 0; i < numberOfElements; i++ {
		ulids[i] = GetUlid()
	}

	return ulids
}

func GetDoubleUidNoTime() string {
	// Create new uniqueid
	uuidString1 := uuid.NewString()
	uuidString2 := uuid.NewString()

	uuidString1 = strings.ToUpper(uuidString1)
	uuidString1 = strings.Replace(uuidString1, "-", "", -1)

	uuidString2 = strings.ToUpper(uuidString2)
	uuidString2 = strings.Replace(uuidString2, "-", "", -1)

	return fmt.Sprintf("%s%s", uuidString1, uuidString2)
}

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func AllowCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "token, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func WriteResponse(w http.ResponseWriter, ro any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// w.WriteHeader(http.StatusOK)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ro)
}

func WriteListResponse(w http.ResponseWriter, lro ListResponseObject) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(lro)
}

func SendEmailWithPort(smtpServer string, smtpPort string, smtpUser string, smtpPassword string, from string, to []string, subject string, message string) error {
	addr := smtpServer + ":" + smtpPort

	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := "<html><body>" + message + "</body></html>"

	msg := []byte("To: " + strings.Join(to[:], ",") + "\r\n" + "Subject:" + subject + "\r\n" + mime + body)

	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpServer)
	err := smtp.SendMail(addr, auth, from, to, msg)

	if err != nil {
		return err
	}

	return nil
}

func SendEmail(smtpServer string, smtpUser string, smtpPassword string, from string, to []string, subject string, message string) error {
	return SendEmailWithPort(smtpServer, "587", smtpUser, smtpPassword, from, to, subject, message)
}

func GetJsonFromFile(fileName string) ([]byte, error) {
	// Open our jsonFile
	jsonFile, err := os.Open(fileName)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened data.json")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	jsonData, err := io.ReadAll(jsonFile)
	return jsonData, err
}

func WriteInvalidResponse(w http.ResponseWriter, code string, message string) {
	var ro *ResponseObject = new(ResponseObject)
	ro.Code = code
	ro.Data = message
	WriteResponse(w, *ro, http.StatusOK)
}

func WriteInvalidResponseWithStatus(w http.ResponseWriter, code string, message string, status int) {
	var ro *ResponseObject = new(ResponseObject)
	ro.Code = code
	ro.Data = message
	WriteResponse(w, *ro, status)
}

func WriteValidResponse(w http.ResponseWriter, code string, message any) {
	var ro *ResponseObject = new(ResponseObject)
	ro.Code = code
	ro.Data = message
	WriteResponse(w, *ro, http.StatusOK)
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

func ValidateToken(db *gorm.DB, token string) bool {
	var tokenId int
	sql := "SELECT id FROM tokens WHERE uniqueid=? AND expiration_date > NOW();"
	db.Raw(sql, token).Scan(&tokenId)

	if tokenId == 0 {
		return false
	} else {
		return true
	}
}

func CheckMultipleValues(db *gorm.DB, tableName string, w http.ResponseWriter, r *http.Request) {
	var checks CheckArray
	err := json.NewDecoder(r.Body).Decode(&checks)
	if err != nil {
		WriteInvalidResponse(w, "ko", "Error decoding params")
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
			WriteInvalidResponse(w, "ko", "Error evaluating items")
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

	WriteValidResponse(w, "ok", returnObject)
}

func DeleteItem(tableName string, w http.ResponseWriter, r *http.Request) {
	AllowCors(&w)

	if (*r).Method == "OPTIONS" {
		return
	}

	// Check method type
	if r.Method != "POST" {
		WriteInvalidResponse(w, "ko", "Invalid data")
		return
	}

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,  // Slow SQL threshold
			LogLevel:                  logger.Error, // Log level
			IgnoreRecordNotFoundError: true,         // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,        // Disable color
		},
	)

	db, err := gorm.Open(mysql.Open(Dsn), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		WriteInvalidResponse(w, "ko", "Error opening the database")
		return
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Println("Error requesting late db close")
	}
	defer sqlDB.Close()

	// Check and validate token
	token := r.Header.Get("token")
	if token == "" || !ValidateToken(db, token) {
		WriteInvalidResponse(w, "ko-999", "Invalid token")
		return
	}

	// Read request body
	var itemToBeDeleted ItemToBeDeleted
	reqBody, _ := io.ReadAll(r.Body)
	json.Unmarshal(reqBody, &itemToBeDeleted)

	if itemToBeDeleted.Uniqueid == "" {
		WriteInvalidResponse(w, "ko", "Invalid data")
		return
	}

	var counter int
	sql := "SELECT COUNT(*) FROM " + tableName + " WHERE uniqueid=?;"
	db.Raw(sql, itemToBeDeleted.Uniqueid).Scan(&counter)

	if counter == 0 {
		WriteInvalidResponse(w, "ko", "Invalid parameter uid")
		return
	}

	sql = "DELETE FROM " + tableName + " WHERE uniqueid='" + itemToBeDeleted.Uniqueid + "';"
	db.Exec(sql)

	var ro *ResponseObject = new(ResponseObject)
	ro.Code = "ok"
	ro.Data = "Operation completed"
	WriteResponse(w, *ro, http.StatusOK)
}

func stringWithCharset(length int, charset string) string {
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func GetRandomString(length int) string {
	var charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	newString := stringWithCharset(length, charset)
	return newString
}

func GetRandomLowercaseString(length int) string {
	var charset string = "abcdefghijklmnopqrstuvwxyz0123456789"

	newString := stringWithCharset(length, charset)
	return newString
}

func LoadConfiguration(file string) Config {
	var config Config
	configFile, err := os.Open(file)

	if err != nil {
		fmt.Println(err.Error())
	}

	defer configFile.Close()

	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	return config
}

func GetDb(config Config) (*gorm.DB, error) {
	cfg := mysqlxx.Config{
		User:   config.Database.Username,
		Passwd: config.Database.Password,
		DBName: config.Database.DatabaseName,
		Addr:   config.Database.Host + ":" + config.Database.Port,
		Net:    "tcp",
		// TLSConfig: "custom",
	}

	if config.Database.Ssl {
		cfg.TLSConfig = "custom"

		rootCertPool := x509.NewCertPool()
		pem, err := os.ReadFile(config.Database.SslCertificate)
		if err != nil {
			log.Fatal(err)
		}
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			log.Fatal("Failed to append PEM.")
		}
		mysqlxx.RegisterTLSConfig("custom", &tls.Config{
			ServerName: config.Database.Host,
			RootCAs:    rootCertPool,
		})

	}

	dsn := cfg.FormatDSN()

	mysqlDb, err := sql.Open("mysql", dsn)

	if err != nil {
		fmt.Println("Error")
		return nil, errors.New("can't create database")
	}

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,  // Slow SQL threshold
			LogLevel:                  logger.Error, // Log level
			IgnoreRecordNotFoundError: true,         // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,        // Disable color
		},
	)

	db, err := gorm.Open(mysql.New(mysql.Config{
		Conn: mysqlDb,
	}), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		return nil, errors.New("can't create GORM database")
	}

	return db, nil
}

func GetDbData(config Config) (*gorm.DB, *sql.DB, error) {
	Dsn = config.Database.Username + ":" + config.Database.Password + "@tcp(" + config.Database.Host + ":" + config.Database.Port + ")/" + config.Database.DatabaseName + "?charset=utf8mb4&parseTime=True&loc=Local"

	return actualGetDbData()
}

func GetDbDataWithoutConfig() (*gorm.DB, *sql.DB, error) {
	return actualGetDbData()
}

func actualGetDbData() (*gorm.DB, *sql.DB, error) {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,  // Slow SQL threshold
			LogLevel:                  logger.Error, // Log level
			IgnoreRecordNotFoundError: true,         // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,        // Disable color
		},
	)

	// Create main database DSN and open db
	db, err := gorm.Open(mysql.Open(Dsn), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		return nil, nil, errors.New("error opening database")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, errors.New("error getting sql db")
	}

	return db, sqlDB, nil
}

func CreateListSql(sql string, sortColumn string, sortOrder string, page int, pageSize int) string {
	if sortColumn != "" && sortOrder != "" {
		sql += " ORDER BY " + sortColumn + " " + sortOrder
	}

	sql += " LIMIT " + strconv.Itoa((page * pageSize)) + ", " + strconv.Itoa(pageSize)

	sql = strings.Replace(sql, ";", "", 1)

	return sql
}

func SaveListParametersInSession(sessionManager *scs.SessionManager, r *http.Request, prefix string, data map[string]interface{}, params map[string]interface{}) {
	sortColumn, ok := data["SortColumn"].(string)

	if !ok {
		sortColumn = ""
	}

	sortOrder, ok := data["SortOrder"].(string)

	if !ok {
		sortOrder = ""
	}

	page, ok := data["Page"].(int)
	if !ok {
		page = 0
	}

	pageSize, ok := data["PageSize"].(int)
	if !ok {
		pageSize = 10
	}

	sessionManager.Put(r.Context(), prefix+"-sortColumn", sortColumn)
	sessionManager.Put(r.Context(), prefix+"-sortOrder", sortOrder)
	sessionManager.Put(r.Context(), prefix+"-page", page)
	sessionManager.Put(r.Context(), prefix+"-pageSize", pageSize)

	for key, val := range params {
		sessionManager.Put(r.Context(), prefix+"-"+key, val)
	}
}

func GetListParametersFromSession(sessionManager *scs.SessionManager, r *http.Request, prefix string, defaultColumn string, defaultDirection string, defaultGridSize int, extraKeys []string) SessionListParameters {
	sessionListParameters := &SessionListParameters{
		SortOrder:  sessionManager.GetString(r.Context(), prefix+"-sortOrder"),
		SortColumn: sessionManager.GetString(r.Context(), prefix+"-sortColumn"),
		Page:       sessionManager.GetInt(r.Context(), prefix+"-page"),
		PageSize:   sessionManager.GetInt(r.Context(), prefix+"-pageSize"),
	}

	if sessionListParameters.SortColumn == "" {
		sessionListParameters.SortColumn = defaultColumn
	}

	if sessionListParameters.SortOrder == "" {
		sessionListParameters.SortOrder = defaultDirection
	}

	if sessionListParameters.PageSize == 0 {
		sessionListParameters.PageSize = defaultGridSize
	}

	extraData := make(map[string]interface{})

	for _, key := range extraKeys {
		if sessionManager.Exists(r.Context(), prefix+"-"+key) {
			extraData[key] = sessionManager.GetString(r.Context(), prefix+"-"+key)
		}
	}

	sessionListParameters.ExtraData = extraData

	return *sessionListParameters
}

func StringReplacer(templateString string, elements map[string]interface{}) string {
	t := template.Must(template.New("sql").Parse(templateString))

	builder := &strings.Builder{}
	if err := t.Execute(builder, elements); err != nil {
		return ""
	}

	s := builder.String()
	return s
}

func InitListParameters(r *http.Request) (map[string]interface{}, map[string]interface{}) {
	// Get list query parameters (lower case)
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil {
		page = 0
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("page_size"))
	if err != nil {
		pageSize = 10
	}

	sortColumn := r.URL.Query().Get("sort_column")
	sortOrder := r.URL.Query().Get("sort_order")

	// Search parameters
	whereCondition := "WHERE 1=@dummy"
	params := make(map[string]interface{})
	params["dummy"] = 1

	data := map[string]interface{}{
		"SortColumn":     sortColumn,
		"SortOrder":      sortOrder,
		"Page":           page,
		"PageSize":       pageSize,
		"StartLimit":     page * pageSize,
		"WhereCondition": whereCondition,
	}

	return data, params
}

func InitListParametersSpg(r *http.Request) (map[string]interface{}, map[string]interface{}) {
	// Get list query parameters (lower case)
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil {
		page = 0
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil {
		pageSize = 10
	}

	sortColumn := r.URL.Query().Get("sortColumn")
	sortOrder := r.URL.Query().Get("sortOrder")

	// Search parameters
	whereCondition := "WHERE 1=@dummy"
	params := make(map[string]interface{})
	params["dummy"] = 1

	data := map[string]interface{}{
		"SortColumn":     sortColumn,
		"SortOrder":      sortOrder,
		"Page":           page,
		"PageSize":       pageSize,
		"StartLimit":     page * pageSize,
		"WhereCondition": whereCondition,
	}

	return data, params
}

type S3PutObjectAPI interface {
	PutObject(ctx context.Context,
		params *s3.PutObjectInput,
		optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func PutFile(c context.Context, api S3PutObjectAPI, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return api.PutObject(c, input)
}

func SendToS3(s3data S3Data, objectName string) error {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(), config.WithRegion(s3data.AwsRegionName),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AwsAccessKeyId, s3data.AwsSecretAccessKey, "")))

	if err != nil {
		return errors.New("can't connect to Amazon S3")
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	file, err := os.Open("/tmp/" + objectName)

	if err != nil {
		return errors.New("unable to open file")
	}

	defer file.Close()

	input := &s3.PutObjectInput{
		Bucket: &s3data.AwsBucketName,
		Key:    &objectName,
		Body:   file,
	}

	_, err = PutFile(context.TODO(), client, input)
	if err != nil {
		return errors.New("unable to upload file")
	}

	return nil
}

func DownloadFromS3(s3data S3Data, objectName string) (string, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(), config.WithRegion(s3data.AwsRegionName),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AwsAccessKeyId, s3data.AwsSecretAccessKey, "")))

	if err != nil {
		return "", errors.New("can't connect to Amazon S3")
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	result, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s3data.AwsBucketName),
		Key:    aws.String(objectName),
	})

	if err != nil {
		return "", err
	}

	pointPosition := strings.LastIndex(objectName, ".")
	extension := objectName[pointPosition:]

	fileName := fmt.Sprintf("/tmp/%s%s", GetUid(), extension)

	defer result.Body.Close()
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return "", err
	}
	_, err = file.Write(body)

	if err != nil {
		return "", err
	}

	return fileName, nil
}

func GetFileContentType(fileName string) (string, error) {
	// Open the file whose type you
	// want to check
	file, err := os.Open(fileName)

	if err != nil {
		panic(err)
	}

	defer file.Close()

	// to sniff the content type only the first
	// 512 bytes are used.

	buf := make([]byte, 512)

	_, err = file.Read(buf)

	if err != nil {
		return "", err
	}

	// the function that actually does the trick
	contentType := http.DetectContentType(buf)

	return contentType, nil
}

func GetFileContent(filename string) ([]byte, error) {
	file, err := os.Open(filename)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}

	var size int64 = stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(bytes)

	return bytes, err
}

func GetTitleString(titleString string) string {
	titleString = strings.ToLower(titleString)
	caser := cases.Title(language.Italian)
	return caser.String(titleString)
}

func CreateUserName(firstname string, lastname string) string {
	re, err := regexp.Compile(`[^\w]`)
	if err != nil {
		log.Fatal(err)
	}

	firstname = re.ReplaceAllString(firstname, "")
	lastname = re.ReplaceAllString(lastname, "")

	username := firstname + "." + lastname
	username = strings.ToLower(username)
	return username
}

func GetMd5Hash(originalString string) string {
	data := []byte(originalString)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func JoinIntArray(values []int, delim string) string {
	stringValues := make([]string, 0)
	for _, value := range values {
		stringValues = append(stringValues, fmt.Sprint(value))
	}

	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(stringValues)), delim), "[]")
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

func CompareDates(t1 time.Time, t2 time.Time) bool {
	return t1.Truncate(24 * time.Hour).Equal(t2.Truncate(24 * time.Hour))
}

// func GetLocalizedString(localizer *i18n.Localizer, messageId string) string {
// 	localizeConfigWelcome := i18n.LocalizeConfig{
// 		MessageID: messageId,
// 	}

// 	localizedString, err := localizer.Localize(&localizeConfigWelcome) //2
// 	if err != nil {
// 		log.Println("err:", err)
// 		return messageId
// 	}

// 	return localizedString
// }

// func GetTranslations(bundle *i18n.Bundle, keys []string, language string) map[string]interface{} {
// 	localizer := i18n.NewLocalizer(bundle, language)
// 	translations := make(map[string]interface{})

// 	for _, key := range keys {
// 		translations[key] = GetLocalizedString(localizer, key)
// 	}

// 	return translations
// }

func InitTranslationsAtStartupTime(db *gorm.DB, localeFilePosition string) (map[string]interface{}, error) {
	var locales []Locale
	sql := `SELECT * FROM locales;`
	result := db.Raw(sql).Scan(&locales)

	if result.Error != nil {
		return nil, errors.New("can't open locale table")
	}

	translations := make(map[string]interface{})
	for _, locale := range locales {
		translations[locale.Lang] = make(map[string]interface{})
	}

	var localeStrings []LocaleString
	sql = `SELECT * FROM locale_strings;`
	result = db.Raw(sql).Scan(&localeStrings)
	if result.Error != nil {
		return nil, errors.New("can't open locale table")
	}

	for _, localeString := range localeStrings {
		var jsonData []Translation
		err := json.Unmarshal(localeString.JsonData, &jsonData)

		if err != nil {
			return nil, err
		}

		for _, jsonElement := range jsonData {
			elements, ok := translations[jsonElement.LangCode].(map[string]interface{})
			if !ok {
				return nil, err
			}
			elements[localeString.ElementKey] = jsonElement.LangValue
			translations[jsonElement.LangCode] = elements
		}
	}

	return translations, nil
}

func JoinIntArrayToString(intArray []int, delim string) string {
	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(intArray)), delim), "[]")
}

func (writer LogWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().Format("2006-01-02 15:04:05") + " " + string(bytes))
}

func GetIntPointerValue(data any, fieldName string) *int {
	pointToStruct := reflect.ValueOf(data)

	if pointToStruct.Kind() != reflect.Pointer {
		return nil
	}

	curStruct := pointToStruct.Elem()

	if curStruct.Kind() != reflect.Struct {
		return nil
	}
	curField := curStruct.FieldByName(fieldName)
	if !curField.IsValid() {
		return nil
	}

	if curField.Elem().CanInt() {
		elem := curField.Elem()
		if elem.Int() == 0 {
			return nil
		} else {
			value := int(elem.Int())
			return &value
		}
	}

	return nil
}

func AesEncrypt(textString string, key []byte) (string, error) {
	text := []byte(textString)
	// key := []byte(keyString)

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		return "", err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return "", err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return "", err
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.

	encryptedBytes := gcm.Seal(nonce, nonce, text, nil)
	encryptedString := hex.EncodeToString(encryptedBytes)

	return encryptedString, nil

}

func AesDecrypt(encryptedString string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedString)
	if err != nil {
		return "", err
	}
	// key := []byte(keyString)

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func Get32BytesKeyFromPassword(password string) ([]byte, error) {
	salt := make([]byte, 8)
	rand.Read(salt)

	dk, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return dk, nil
}

type S3DeleteObjectAPI interface {
	DeleteObject(ctx context.Context,
		params *s3.DeleteObjectInput,
		optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// DeleteItem deletes an object from an Amazon Simple Storage Service (Amazon S3) bucket
// Inputs:
//
//	c is the context of the method call, which includes the AWS Region
//	api is the interface that defines the method call
//	input defines the input arguments to the service call.
//
// Output:
//
//	If success, a DeleteObjectOutput object containing the result of the service call and nil
//	Otherwise, an error from the call to DeleteObject
func DeleteS3Item(c context.Context, api S3DeleteObjectAPI, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return api.DeleteObject(c, input)
}

func DeleteFromS3(s3data S3Data, objectName string) error {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(), config.WithRegion(s3data.AwsRegionName),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AwsAccessKeyId, s3data.AwsSecretAccessKey, "")))

	if err != nil {
		return errors.New("can't connect to Amazon S3")
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	// client.DeleteObject()

	input := &s3.DeleteObjectInput{
		Bucket: &s3data.AwsBucketName,
		Key:    &objectName,
	}

	_, err = DeleteS3Item(context.TODO(), client, input)
	if err != nil {
		return err
	}

	return nil
}

func GetIntQueryStringParameter(r *http.Request, parameterName string) int {
	parameterValue, err := strconv.Atoi(r.PostForm.Get(parameterName))
	if err != nil {
		return 0
	} else {
		return parameterValue
	}
}

func GetFloatQueryStringParameter(r *http.Request, parameterName string) float64 {
	parameterValue, err := strconv.ParseFloat(r.PostForm.Get(parameterName), 64)
	if err != nil {
		return 0
	} else {
		return parameterValue
	}
}

func GetBoolQueryStringParameter(r *http.Request, parameterName string) bool {
	parameterValue, err := strconv.ParseBool(r.PostForm.Get(parameterName))

	if err != nil {
		return false
	} else {
		return parameterValue
	}
}

func GetCustomError(message string, code int) error {
	return &CustomError{
		StatusCode: code,
		Err:        message,
	}
}

func GetCustomErrorFromAnotherError(err error, message string, code int) error {
	completeMessage := fmt.Sprintf("%s -> %s", message, err)
	return &CustomError{
		StatusCode: code,
		Err:        completeMessage,
	}
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

func AesGetIv(key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		return nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

func AesEncryptFixedIv(textString string, key []byte, nonce []byte) (string, error) {
	text := []byte(textString)

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		return "", err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return "", err
	}

	encryptedBytes := gcm.Seal(nil, nonce, text, nil)
	encryptedString := hex.EncodeToString(encryptedBytes)

	return encryptedString, nil

}

func AesDecryptFixedIv(encryptedString string, key []byte, nonce []byte) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedString)
	if err != nil {
		return "", err
	}
	// key := []byte(keyString)

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func GetCryptoStuff(cryptoItem string) (string, []byte, error) {
	if cryptoItem == "" {
		return "", nil, errors.New("invalid string")
	}

	nonceString := cryptoItem[:24]
	cryptoKey := cryptoItem[24:]

	nonce, err := hex.DecodeString(nonceString)
	if err != nil {
		return "", nil, err
	}

	return cryptoKey, nonce, nil
}

func NewTelegram(token string, chatId string) Telegram {
	t := Telegram{}
	t.SetUrl(token, chatId)
	return t
}

/* Get float32, float64, int value from a string array */
func GetNumberColValue[T float64 | float32 | int](row []string, position int, mode T) T {
	if len(row) < (position + 1) {
		return 0
	}

	switch any(mode).(type) {
	case int:
		number, err := strconv.Atoi(row[position])
		if err != nil {
			return 0
		}

		return T(number)
	case float32:
		number, err := strconv.ParseFloat(row[position], 32)
		if err != nil {
			return 0
		}

		return T(number)
	case float64:
		number, err := strconv.ParseFloat(row[position], 64)
		if err != nil {
			return 0
		}

		return T(number)
	default:
		return 0
	}
}

func DeleteFromDoS3(s3data DoS3Data, objectName string) error {
	// Create a custom resolver for DigitalOcean Spaces
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: s3data.SpacesUrl,
		}, nil
	})

	// Configure the AWS SDK
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(s3data.Region),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AccessKey, s3data.Secret, "")),
	)
	if err != nil {
		return err
	}

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	// client.DeleteObject()

	input := &s3.DeleteObjectInput{
		Bucket: &s3data.BucketName,
		Key:    &objectName,
	}

	_, err = DeleteS3Item(context.TODO(), client, input)
	if err != nil {
		return err
	}

	return nil
}

func DownloadFromDoS3(s3data DoS3Data, objectName string) (string, error) {
	// Create a custom resolver for DigitalOcean Spaces
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: s3data.SpacesUrl,
		}, nil
	})

	// Configure the AWS SDK
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(s3data.Region),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3data.AccessKey, s3data.Secret, "")),
	)
	if err != nil {
		return "", err
	}
	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)

	result, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s3data.BucketName),
		Key:    aws.String(objectName),
	})

	if err != nil {
		return "", err
	}

	pointPosition := strings.LastIndex(objectName, ".")
	extension := objectName[pointPosition:]

	fileName := fmt.Sprintf("/tmp/%s%s", GetUid(), extension)

	defer result.Body.Close()
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return "", err
	}
	_, err = file.Write(body)

	if err != nil {
		return "", err
	}

	return fileName, nil
}

func StructToMap(input interface{}) (map[string]interface{}, error) {
	output := make(map[string]interface{})
	v := reflect.ValueOf(input)

	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		output[field.Name] = v.Field(i).Interface()
	}

	return output, nil
}
