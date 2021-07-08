package fishook

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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
type Token struct {
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

var KeyLogFile = "./fishook/token.key"
var KeyTmpFile = "./fishook/token.key.tmp"

// SetLogFile set log file path.
func (token *Token) SetLogFile(path string) {
	KeyLogFile = path
}

// SetLogTmpFile set log tmp file path.
func (token *Token) SetLogTmpFile(path string) {
	KeyTmpFile = path
}

// Log key-persistence.
func (token *Token) WriteLog() error {
	err := os.Rename(KeyLogFile, KeyTmpFile)
	if err != nil {
		return err
	}

	logFile, err := os.OpenFile(KeyLogFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}
	defer logFile.Close()

	data, err := json.Marshal(&token.KeyLogs)
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
func (token *Token) ReadLog() error {

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

	err = json.Unmarshal(data, &keyLogs)
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
func (token *Token) CreateTokenKeys(timestamp int64) {
	token.Timestamp = timestamp
	token.ReadyChan = make(chan bool)
	token.ReadLog()
	go token.keysTimer()
}

// keysTimer key will auto change each time interval.
func (token *Token) keysTimer() error {

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
func (token *Token) CreateToken(timestamp int64, params map[string]interface{}) (tokenStr string) {

	now := time.Now()

	expStr := strconv.FormatInt(now.Unix()+token.Timestamp, 10)
	if timestamp > 0 && timestamp <= token.Timestamp {
		expStr = strconv.FormatInt(now.Unix()+timestamp, 10)
	}

	head := `{"typ":"JWT","alg":"HS256"}`
	payload := `{"exp":"` + expStr + `"`

	for k, v := range params {
		switch v := v.(type) {
		case string:
			payload = payload + `,` + `"` + k + `":"` + v + `"`
		case float64:
			payload = payload + `,` + `"` + k + `":` + strconv.FormatFloat(v, 'f', -1, 64) + ``
		case int64:
			payload = payload + `,` + `"` + k + `":` + strconv.FormatInt(v, 10) + ``
		default:
			return ""
		}
	}

	payload = payload + `}`

	key := token.Keys[0]

	headBase64 := base64.StdEncoding.EncodeToString([]byte(head))
	payloadBase64 := base64.StdEncoding.EncodeToString([]byte(payload))
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(key))

	base64Str := headBase64 + "." + payloadBase64 + "~" + keyBase64

	signatureBase64 := toSha256(base64Str)
	return headBase64 + "." + payloadBase64 + "." + signatureBase64
}

// ValidateToken validate token.
func (token *Token) ValidateToken(tokenStr string) (tokenResult Result, params map[string]string) {

	if tokenStr == "" {
		return Failure, nil
	}

	params = tokenPayloadParams(tokenStr)

	exp, _ := strconv.ParseInt(params["exp"], 10, 64)
	if exp < time.Now().Unix() {
		return Timeout, nil
	}

	for i := 0; i < 2; i++ {
		keyBase64 := base64.StdEncoding.EncodeToString([]byte(token.Keys[i]))
		base64Str := strings.Split(tokenStr, ".")[0] + "." + strings.Split(tokenStr, ".")[1] + "~" + keyBase64
		signatureBase64 := strings.Split(tokenStr, ".")[2]
		if signatureBase64 == toSha256(base64Str) {
			return Success, params
		}
	}
	return Failure, nil
}

// tokenPayloadParams get token params.
func tokenPayloadParams(tokenStr string) map[string]string {
	splitStr := strings.Split(tokenStr, ".")[1]
	payload, _ := base64.StdEncoding.DecodeString(splitStr)
	params := make(map[string]string)
	json.Unmarshal(payload, &params)
	return params
}

// toSha256 sha256.
func toSha256(str string) string {
	bytes := []byte(str)
	hash := sha256.Sum256(bytes)
	result := hex.EncodeToString(hash[:])
	return result
}
