package goutils

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

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

func StructToMap(input interface{}) (map[string]interface{}, error) {
	output := make(map[string]interface{})
	v := reflect.ValueOf(input)

	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		output[field.Name] = v.Field(i).Interface()
	}

	return output, nil
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

func JoinIntArrayToString(intArray []int, delim string) string {
	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(intArray)), delim), "[]")
}

func JoinIntArray(values []int, delim string) string {
	stringValues := make([]string, 0)
	for _, value := range values {
		stringValues = append(stringValues, fmt.Sprint(value))
	}

	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(stringValues)), delim), "[]")
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
