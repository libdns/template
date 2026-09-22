module github.com/libdns/mittwald/libdnstest

go 1.26.8

require (
	github.com/libdns/libdns v1.1.1
	github.com/libdns/mittwald v0.0.0
)

require (
	github.com/mittwald/api-client-go v0.2.240 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace github.com/libdns/mittwald => ../

replace github.com/libdns/libdns => github.com/libdns/libdns v1.2.0-alpha.1
