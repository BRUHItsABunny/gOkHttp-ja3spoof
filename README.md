# gOkHttp ja3spoof
JA3 spoofing addon for [gOkHttp](https://github.com/BRUHItsABunny/gOkHttp).

## Installation
```shell
go get -u github.com/BRUHItsABunny/gOkHttp-ja3spoof
```

## Usage
```go
package main

import (
	"context"
	"fmt"
	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_ja3spoof "github.com/BRUHItsABunny/gOkHttp-ja3spoof"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	utls "github.com/refraction-networking/utls"
)

func main() {
	browser := device_utils.AvailableBrowsers["brave"]["1.50.114"]
	hClient, err := gokhttp.NewHTTPClient(
		gokhttp_ja3spoof.NewJa3SpoofingOption(browser, &utls.Config{InsecureSkipVerify: true}),
	)
	if err != nil {
		panic(err)
	}

	req, err := gokhttp_requests.MakeGETRequest(context.Background(), "https://tls.peet.ws/api/clean")
	if err != nil {
		panic(err)
	}
	
	resp, err := hClient.Do(req)
	if err != nil {
		panic(err)
	}
	
	result, err := gokhttp_responses.ResponseText(resp)
	if err != nil {
		panic(err)
	}
	
	fmt.Println(result)
}
```
