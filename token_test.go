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
			tokenStr := token.CreateToken(5, &User{Username: "Test", Password: "123456"})
			time.Sleep(time.Second)
			token.ValidateToken(tokenStr)
			time.Sleep(time.Second)
			token.ValidateToken(tokenStr)
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
