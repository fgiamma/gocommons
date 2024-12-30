package uids

import (
	"fmt"
	"strings"
	"time"

	cryptorand "crypto/rand"

	"github.com/google/uuid"
	"github.com/oklog/ulid"
)

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
