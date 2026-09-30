# Live tests for enum

Runs the [libdnstest](https://github.com/libdns/libdns/tree/master/libdnstest) suite against the enum API.

```bash
export ENUM_API_KEY="enum_sk_..."
export ENUM_PROJECT_ID="proj-..."
export ENUM_TEST_ZONE="example.com." # with trailing dot

go test -v
```

HTTPS and SVCB are skipped because enum does not support them. NS is skipped because the suite uses a TTL of 300s and enum requires at least 3600s for NS records.
