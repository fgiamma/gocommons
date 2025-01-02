package gohttp

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

type ResponseObject struct {
	Code string      `json:"code"`
	Data interface{} `json:"data"`
}

type ListResponseObject struct {
	TotalRows   int         `json:"totalRows"`
	CurrentPage interface{} `json:"currentPage"`
}

func WriteResponse(w http.ResponseWriter, ro any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// w.WriteHeader(http.StatusOK)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ro)
}

func WriteValidResponse(w http.ResponseWriter, code string, message any) {
	var ro *ResponseObject = new(ResponseObject)
	ro.Code = code
	ro.Data = message
	WriteResponse(w, *ro, http.StatusOK)
}

func WriteInvalidResponse(w http.ResponseWriter, code string, message string) {
	var ro *ResponseObject = new(ResponseObject)
	ro.Code = code
	ro.Data = message
	WriteResponse(w, *ro, http.StatusOK)
}

func AllowCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "token, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func WriteListResponse(w http.ResponseWriter, lro ListResponseObject) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(lro)
}

// func WriteInvalidResponse(w http.ResponseWriter, code string, message string) {
// 	var ro *ResponseObject = new(ResponseObject)
// 	ro.Code = code
// 	ro.Data = message
// 	WriteResponse(w, *ro, http.StatusOK)
// }

func WriteInvalidResponseWithStatus(w http.ResponseWriter, code string, message string, status int) {
	var ro *ResponseObject = new(ResponseObject)
	ro.Code = code
	ro.Data = message
	WriteResponse(w, *ro, status)
}

// func WriteValidResponse(w http.ResponseWriter, code string, message any) {
// 	var ro *ResponseObject = new(ResponseObject)
// 	ro.Code = code
// 	ro.Data = message
// 	WriteResponse(w, *ro, http.StatusOK)
// }

func CreateListSql(sql string, sortColumn string, sortOrder string, page int, pageSize int) string {
	if sortColumn != "" && sortOrder != "" {
		sql += " ORDER BY " + sortColumn + " " + sortOrder
	}

	sql += " LIMIT " + strconv.Itoa((page * pageSize)) + ", " + strconv.Itoa(pageSize)

	sql = strings.Replace(sql, ";", "", 1)

	return sql
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
