# libdnstest for mittwald

Runs the [libdns test suite](https://github.com/libdns/libdns/tree/master/libdnstest) against a real mStudio domain. The suite creates records under names starting with `test-` and leaves some of them in place; a second run expects them to be gone, so delete them before running it again.

```sh
MITTWALD_API_TOKEN=... MITTWALD_TEST_ZONE=example.com. go test -v ./...
```

`MITTWALD_API_URL` sends the requests to another API host, such as a test system of mittwald.
