package fishook

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCreateTokenKeys(t *testing.T) {
	token := new(Token[User])
	token.CreateTokenKeys(10)
	<-token.ReadyChan
	group := new(sync.WaitGroup)
	var num int64
	for i := 0; i < 100000; i++ {
		group.Add(1)
		go func() {
			now := time.Now()
			tokenStr := token.CreateToken(now, 5, 3, &User{Username: "Test", Password: "123456"})
			time.Sleep(time.Second)
			now = time.Now()
			token.ValidateToken(now, tokenStr)
			time.Sleep(time.Second)
			now = time.Now()
			token.ValidateToken(now, tokenStr)
			atomic.AddInt64(&num, 1)
			group.Done()
		}()
	}
	group.Wait()
	fmt.Println(num)
}

// User test object
type User struct {
	Username string
	Password string
}
