## Testing

A sample test is included to help you verify that your provider correctly implements the [libdns contract](https://github.com/libdns/libdns/blob/master/libdns.go).

To use it, create as `provider_test.go` in the same directory as you provider.

```go

import (
	...
	"github.com/pbergman/provider/test"
)

func TestProvider(t *testing.T) {
	test.RunProviderTests(t, &Provider{
        ApiKey:  os.Getenv("API_KEY"),
        ...
	})
}

```

After that, you should be able to run your tests like this:

```bash

API_KEY=.... go test -v 
```