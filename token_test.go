package fishook

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCreateTokenKeys(t *testing.T) {
	token := new(Token)
	token.CreateTokenKeys(10)
	<-token.ReadyChan
	group := new(sync.WaitGroup)
	var num int64
	for i := 0; i < 100000; i++ {
		group.Add(1)
		go func() {
			params := make(map[string]interface{})
			tokenStr := token.CreateToken(5, params)
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
