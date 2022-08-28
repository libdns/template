Dinahosting DNS for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/dinahosting)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [Dinahosting API](https://es.dinahosting.com/api), allowing you to manage DNS records for your domains. 


## Limitations
As this library is mainly intended to be used as a [Caddy](https://github.com/caddyserver/caddy) plugin for solving ACME challenges and adding [dynamic dns](https://github.com/mholt/caddy-dynamicdns) capabilities,(and also beacause Dinahosting API is quite messy to work with) **it only supports A and TXT records for the moment.** I may add more in the future. 


## Authenticating
Dinahosting does not provide API keys, so you will need to use the username and password of your account. 

## Testing 
You can easily test the library against your account. Just add your details to the test file `provider_test.go`:

```go
// To be able to run the tests succesfully please replace this constants with you actual account details.
//
// This tests assumes you have a test zone with only 1 A type record
// they will create, modify and delete some records on that zone
// but it should be at the original state afer finishing runinng.
const (
	username = "YOUR_USERNAME"
	password = "YOUR_PASSWORD"
	zone     = "example.com"
	ip       = "YOUR A RECORD IP"
)
```
 and run the tests:

```
go test provider_test.go
```


## Example usage
Here is a minimal example of how to create a new TXT record using this `libdns` provider. 
```go
package main

import (
    "context"

    "github.com/libdns/libdns"
    "github.com/libdns/dinahosting"
)

func main() {
    p := &dinahosting.Provider{
        Username: "YOUR_USERNAME",   // required
        Password: "YOUR_PASSWORD",   // required
    }

    _, err := p.AppendRecords(context.Background(), "example.org.", []libdns.Record{
        {
            Name:  "_acme_whatever",
            Type:  "TXT",
            Value: "123456",
        },
    })
    if err != nil {
        panic(err)
    }
}
```
