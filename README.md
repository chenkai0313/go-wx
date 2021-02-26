# go-wx
微信小程序授权/支付/退款等接口封装


### 使用
```
go get github.com/chenkai0313/go-wx

已封装了延迟队列方法 
```

#### 使用事例
```
package main

import (
	"fmt"
	wxapp "go-wx"
)

func main() {
	cli := wxapp.NewWxApp("yourAppId", "yourAppSecret", "yourPayMchId", "yourApiKey")
	accessToken, err := cli.GetAccessToken()
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("accessToken", accessToken)
}

```