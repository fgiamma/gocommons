package uids

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oklog/ulid"
	"golang.org/x/crypto/scrypt"

	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"

	// "crypto/rand"
	cryptorand "crypto/rand"
	"math/rand"
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

func GetMd5Hash(originalString string) string {
	data := []byte(originalString)
	return fmt.Sprintf("%x", md5.Sum(data))
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
