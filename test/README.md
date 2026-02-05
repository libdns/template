## Testing

This test helper is included to help you verify that your provider correctly implements the [libdns contract](https://github.com/libdns/libdns/blob/master/libdns.go). It can partially test your implementation or do a full test depending on `TestMode` parameter.

To use this, create as `provider_test.go` in the same directory as you provider, initialize your provider and run the test.

## Example

```go

import (
	...
	"github.com/pbergman/provider/test"
)

func TestProvider(t *testing.T) {
    
    var provider = &Provider{
        ApiKey:  os.Getenv("API_KEY"),
        ...
    }
	
    test.RunProviderTests(t, provider, test.TestAll)
}

```

After that, you should be able to run your tests like this:

```bash

API_KEY=.... go test -v 
```

## TestMode

to partially test parts of the interface, you could do something like

```go

test.RunProviderTests(t, provider, test.TestAll^(test.TestDeleter|test.TestAppender))

```

to skip the delete and append test and can be useful when implementing a new provider or debugging. 