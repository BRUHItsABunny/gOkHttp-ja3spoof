module github.com/BRUHItsABunny/gOkHttp-ja3spoof

go 1.24.0

toolchain go1.24.1

replace github.com/ooni/oohttp v0.8.0 => github.com/BRUHItsABunny/oohttp v0.8.0-useragent-fix

replace github.com/refraction-networking/utls v1.6.8-0.20250314010516-e430876b1d82 => github.com/BRUHItsABunny/utls v1.6.7-chrome-133-support

require (
	github.com/BRUHItsABunny/gOkHttp v0.3.7
	github.com/BRUHItsABunny/go-device-utils v0.0.5
	github.com/ooni/oohttp v0.8.0
	github.com/refraction-networking/utls v1.6.8-0.20250314010516-e430876b1d82
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
