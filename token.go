package fishook

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
)

/*
this origin is https://github.com/EvenBoom/token, my open project.
*/

// Result result of action.
type Result string

const (
	// Success success.
	Success Result = "success"
	// Failure Failure.
	Failure Result = "failure"
	// Timeout timeout.
	Timeout Result = "timeout"
)

// Token token.
type Token[T any] struct {
	Keys      [2]string
	Timestamp int64
	Interval  int64
	Ready     bool
	ReadyChan chan bool
	KeyLogs   [2]*KeyLog
}

// KeyLog log of token.
type KeyLog struct {
	Key      string
	Deadline int64
}

// Head head of token
type Head struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	Expire    int64  `json:"exp"`
	Refresh   int64  `json:"ref"`
}

var KeyDir = "./fishook/"
var KeyLogFile = KeyDir + "token.key"
var KeyTmpFile = KeyDir + "token.key.tmp"

// SetLogFile set log file path.
func (token *Token[T]) SetLogFile(path string) {
	KeyLogFile = path
}

// SetLogTmpFile set log tmp file path.
func (token *Token[T]) SetLogTmpFile(path string) {
	KeyTmpFile = path
}

// Log key-persistence.
func (token *Token[T]) WriteLog() error {
	err := os.Rename(KeyLogFile, KeyTmpFile)
	if err != nil {
		return err
	}

	logFile, err := os.OpenFile(KeyLogFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}
	defer logFile.Close()

	data, err := jsoniter.Marshal(&token.KeyLogs)
	if err != nil {
		return err
	}

	_, err = logFile.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// ReadLog key-persistence.
func (token *Token[T]) ReadLog() error {

	err := os.MkdirAll(KeyDir, os.ModeDir)
	if err != nil {
		return err
	}

	logFile, err := os.OpenFile(KeyLogFile, os.O_RDONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}
	defer logFile.Close()

	keyLogs := [2]*KeyLog{}

	data, err := io.ReadAll(logFile)
	if err != nil {
		return err
	}

	err = jsoniter.Unmarshal(data, &keyLogs)
	if err != nil {
		return err
	}

	token.KeyLogs = keyLogs

	now := time.Now()
	timestamp := now.Unix()
	for i, keyLog := range token.KeyLogs {
		if keyLog == nil {
			continue
		}

		if keyLog.Deadline > timestamp+token.Interval {
			token.Interval = keyLog.Deadline - timestamp
		}

		if keyLog.Deadline > timestamp {
			token.Keys[i] = keyLog.Key
		}
	}

	return nil
}

// CreateTokenKeys create keys of token, token's longest expired-time is the double of param key's.
func (token *Token[T]) CreateTokenKeys(timestamp int64) {
	token.Timestamp = timestamp
	token.ReadyChan = make(chan bool)
	token.ReadLog()
	go token.keysTimer()
}

// keysTimer key will auto change each time interval.
func (token *Token[T]) keysTimer() error {

	timestamp := token.Timestamp
	if token.Interval > 0 {
		timestamp = token.Interval
		token.Interval = 0
	} else {

		token.Keys[1] = token.Keys[0]

		ruuid, err := uuid.NewRandom()
		if err != nil {
			return err
		}

		token.Keys[0] = ruuid.String()

		now := time.Now()
		keyLogs := [2]*KeyLog{}
		for i, key := range token.Keys {
			if key == "" {
				continue
			}
			keyLog := new(KeyLog)
			keyLog.Key = key
			keyLog.Deadline = now.Unix() + int64(i+1)*timestamp
			keyLogs[i] = keyLog
		}
		token.KeyLogs = keyLogs
		token.WriteLog()
	}

	if !token.Ready {
		token.Ready = true
		token.ReadyChan <- true
	}

	timer := time.NewTimer(time.Duration(timestamp) * time.Second)
	<-timer.C
	go token.keysTimer()

	return nil
}

// CreateToken create a token.
func (token *Token[T]) CreateToken(now time.Time, expire, refresh int64, tokenLoad *T) (tokenStr string) {

	var tokenHead Head
	tokenHead.Type = "JWT"
	tokenHead.Algorithm = "HS256"
	tokenHead.Expire = now.Unix() + token.Timestamp
	if expire > 0 && expire <= token.Timestamp {
		tokenHead.Expire = now.Unix() + expire
	}
	tokenHead.Refresh = now.Unix() + refresh

	head, _ := jsoniter.Marshal(tokenHead)
	var load []byte
	if tokenLoad != nil {
		load, _ = jsoniter.Marshal(tokenLoad)
	}

	key := token.Keys[0]

	headBase64 := base64.StdEncoding.EncodeToString(head)
	loadBase64 := base64.StdEncoding.EncodeToString(load)
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(key))

	base64Str := headBase64 + "." + loadBase64 + "~" + keyBase64

	signatureBase64 := toSha256(base64Str)
	return headBase64 + "." + loadBase64 + "." + signatureBase64
}

// ValidateToken validate token.
func (token *Token[T]) ValidateToken(now time.Time, tokenStr string) (tokenResult Result, head Head, load *T) {

	if tokenStr == "" {
		return Failure, head, nil
	}

	head, load = token.tokenParams(tokenStr)
	if head.Expire == 0 {
		return Timeout, head, nil
	}

	if head.Expire < now.Unix() {
		return Timeout, head, nil
	}

	for i := 0; i < 2; i++ {
		keyBase64 := base64.StdEncoding.EncodeToString([]byte(token.Keys[i]))
		base64Str := strings.Split(tokenStr, ".")[0] + "." + strings.Split(tokenStr, ".")[1] + "~" + keyBase64
		signatureBase64 := strings.Split(tokenStr, ".")[2]
		if signatureBase64 == toSha256(base64Str) {
			return Success, head, load
		}
	}

	return Failure, head, nil
}

// tokenParams get token params.
func (token *Token[T]) tokenParams(tokenStr string) (head Head, load *T) {

	tokenStrs := strings.Split(tokenStr, ".")
	if len(tokenStrs) < 2 {
		return
	}

	// head
	splitStr := strings.Split(tokenStr, ".")[0]
	data, _ := base64.StdEncoding.DecodeString(splitStr)
	jsoniter.Unmarshal(data, &head)

	// load
	splitStr = strings.Split(tokenStr, ".")[1]
	data, _ = base64.StdEncoding.DecodeString(splitStr)
	load = new(T)
	jsoniter.Unmarshal(data, load)

	return
}

// toSha256 sha256.
func toSha256(str string) string {
	bytes := []byte(str)
	hash := sha256.Sum256(bytes)
	result := hex.EncodeToString(hash[:])
	return result
}
