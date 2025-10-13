package test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/libdns/libdns"
	helper "github.com/pbergman/provider"
)

type TestMode uint64

const (
	TestAppender TestMode = 1 << iota
	TestDeleter
	TestGetter
	TestSetter
	TestZones
	TestAll = TestAppender | TestDeleter | TestGetter | TestSetter | TestZones
)

type Provider interface {
	libdns.RecordAppender
	libdns.RecordDeleter
	libdns.RecordGetter
	libdns.RecordSetter
}

func RunProviderTests(t *testing.T, provider Provider, mode TestMode) {

	var wg sync.WaitGroup

	if zoneListener, ok := provider.(libdns.ZoneLister); ok {
		if TestZones == (TestZones & mode) {
			wg.Add(1)
			t.Run("ListZones", func(t *testing.T) {
				defer wg.Done()
				testListZones(t, zoneListener)
			})
		}
	} else {
		t.Skipf("ListZones not implemented.")
	}

	var zones = getZonesForTesting(t, provider)

	if TestGetter == (TestGetter & mode) {
		t.Run("RecordGetter", func(t *testing.T) {
			wg.Add(1)
			defer wg.Done()
			testRecordGetter(t, provider, zones)
		})
	}

	wg.Wait()

	if TestAppender == (TestAppender & mode) {
		t.Run("RecordAppender", func(t *testing.T) {
			testRecordAppender(t, provider, zones)
		})
	}

	if TestSetter == (TestSetter & mode) {
		t.Run("RecordSetter - Example 1", func(t *testing.T) {
			testRecordsSetExample1(t, provider, zones)
		})

		t.Run("RecordSetter - Example 2", func(t *testing.T) {
			testRecordsSetExample2(t, provider, zones)
		})
	}

	if TestDeleter == (TestDeleter & mode) {
		t.Run("RecordDeleter", func(t *testing.T) {
			testDeleteRecords(t, provider, zones)
		})
	}
}

func printRecords(t *testing.T, records []libdns.Record, invalid libdns.Record, prefix string) {

	var buf = new(bytes.Buffer)
	var writer = tabwriter.NewWriter(buf, 0, 4, 2, ' ', tabwriter.Debug)
	var isWritten = false
	var write = func(prefix string, record libdns.RR) {
		_, _ = fmt.Fprintf(writer, "%s%s\t %s\t %s\t %s\n", prefix, record.Name, record.TTL, record.Type, record.Data)
	}

	for _, record := range records {
		var rr = record.RR()

		if invalid != nil {
			prefix = "✓ "

			if record.RR().Type == invalid.RR().Type && record.RR().Data == invalid.RR().Data && strings.EqualFold(record.RR().Name, invalid.RR().Name) {
				prefix = "× "
				isWritten = true
			}
		}

		write(prefix, rr)
	}

	if false == isWritten && nil != invalid {
		write("× ", invalid.RR())
	}

	_ = writer.Flush()

	scanner := bufio.NewScanner(buf)

	for scanner.Scan() {
		t.Log(scanner.Text())
	}
}

func getZonesForTesting(t *testing.T, p Provider) []string {

	if v, ok := os.LookupEnv("ZONE"); ok {
		return strings.Split(v, ",")
	}

	if o, ok := p.(libdns.ZoneLister); ok {
		zones, err := o.ListZones(context.Background())

		if err != nil {
			t.Fatalf("ListZones failed: %v", err)
		}

		var ret = make([]string, len(zones))

		for idx, zone := range zones {
			ret[idx] = zone.Name
		}

		return ret
	}

	t.Fatal("No valid zones found, either implement libdns.ZoneLister or use ZONE environment variable")

	return nil
}

func testListZones(t *testing.T, provider libdns.ZoneLister) {

	zones, err := provider.ListZones(context.Background())

	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	t.Log("checking if the zone includes trailing dot")

	for _, zone := range zones {
		if strings.HasSuffix(zone.Name, ".") {
			t.Logf("✓ %s", zone.Name)
		} else {
			t.Fatalf("missing trailing dot: %s", zone.Name)
		}
	}

}

func testReturnTypes(t *testing.T, records []libdns.Record) {
	var buf = new(bytes.Buffer)
	var writer = tabwriter.NewWriter(buf, 0, 4, 2, ' ', tabwriter.Debug)

	for _, record := range records {
		switch record.(type) {
		case *libdns.RR, libdns.RR:
			t.Fatalf("expecting specific RR-type instead of the opaque RR struct (%#+v)", record)
		default:
			_, _ = fmt.Fprintf(writer, "✓ %s\t%s\t%T\n", record.RR().Name, record.RR().Type, record)
		}
	}

	_ = writer.Flush()

	scanner := bufio.NewScanner(buf)

	for scanner.Scan() {
		t.Log(scanner.Text())
	}
}

func testRecordGetter(t *testing.T, provider Provider, zones []string) {

	t.Log("not much specials to test except for errors from client and return types")

	for _, zone := range zones {

		records, err := provider.GetRecords(context.Background(), zone)

		if err != nil {
			t.Fatalf("GetRecords failed: %v", err)
		}

		t.Logf("records in zone: \"%s\"", zone)
		printRecords(t, records, nil, " ")

		t.Logf("testing return record types are not of type libdns.RR")
		testReturnTypes(t, records)
	}

}

func testRecordAppender(t *testing.T, provider Provider, zones []string) {

	var records = []libdns.Record{
		libdns.TXT{
			Name: "LibDNS_test_append_records",
			Text: "Proin nec metus in mauris malesuada aliquet",
			TTL:  24 * time.Hour,
		},
		libdns.TXT{
			Name: "LibDNS_test_append_records",
			Text: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			TTL:  24 * time.Hour,
		},
		libdns.TXT{
			Name: "LibDNS_test_append_records",
			Text: "Praesent molestie mi a lorem aliquam maximus.",
			TTL:  24 * time.Hour,
		},
		libdns.TXT{
			Name: "LibDNS_test_append_records",
			Text: "Nulla ultricies eros quis velit tincidunt, in molestie lorem molestie.",
			TTL:  24 * time.Hour,
		},
	}

	t.Log("the contract states it should create records and never change existing records and")
	t.Log("return the records that were created (specific RR-type that correspond to the type)")

	for _, zone := range zones {

		out, err := provider.AppendRecords(context.Background(), zone, records)

		defer provider.DeleteRecords(context.Background(), zone, records)

		if err != nil {
			t.Fatalf("AppendRecords failed: %v", err)
		}

		t.Logf("successfully added %d records to zone %s", len(records), zone)
		t.Log("testing return records in record lists")

		for _, record := range helper.RecordIterator(&records) {
			if false == helper.IsInList(&record, &out) {
				printRecords(t, records, record, " ")
				t.Fatal("returned unexpected records")
			}
		}

		printRecords(t, records, nil, "✓ ")

		t.Logf("testing return record types are not of type libdns.RR")
		testReturnTypes(t, out)

		t.Logf("testing for error while updating records")

		if _, err := provider.AppendRecords(context.Background(), zone, records); err == nil {
			t.Fatalf("expecting failed but didn't")
		}
	}
}

func testRecordsSetExample1(t *testing.T, provider Provider, zones []string) {
	var name = "LibDNS.test.set.records"
	var original = []libdns.Record{
		libdns.Address{Name: name, IP: netip.MustParseAddr("192.0.2.1"), TTL: 1 * time.Hour},
		libdns.Address{Name: name, IP: netip.MustParseAddr("192.0.2.2"), TTL: 1 * time.Hour},
		libdns.TXT{Name: name, Text: "hello world", TTL: 1 * time.Hour},
	}

	var input = []libdns.Record{
		libdns.Address{Name: name, IP: netip.MustParseAddr("192.0.2.3"), TTL: 1 * time.Hour},
	}

	t.Log("will test the following example:")
	t.Log("")
	t.Log("// Example 1:")
	t.Log("//")
	t.Log("//	;; Original zone")
	t.Log("//	example.com. 3600 IN A   192.0.2.1")
	t.Log("//	example.com. 3600 IN A   192.0.2.2")
	t.Log("//	example.com. 3600 IN TXT \"hello world\"")
	t.Log("//")
	t.Log("//	;; Input")
	t.Log("//	example.com. 3600 IN A   192.0.2.3")
	t.Log("//")
	t.Log("//	;; Resultant zone")
	t.Log("//	example.com. 3600 IN A   192.0.2.3")
	t.Log("//	example.com. 3600 IN TXT \"hello world\"")

	for _, zone := range zones {
		out, err := provider.AppendRecords(context.Background(), zone, original)

		if err != nil {
			t.Fatalf("AppendRecords failed: %v", err)
		}

		t.Logf("records appended to zone \"%s\":", zone)
		printRecords(t, out, nil, "✓ ")

		defer provider.DeleteRecords(context.Background(), zone, []libdns.Record{
			libdns.Address{Name: name},
			libdns.TXT{Name: name},
		})

		t.Logf("set record \"%s %s %s %s\":", input[0].RR().Name, input[0].RR().TTL, input[0].RR().Type, input[0].RR().Data)

		ret, err := provider.SetRecords(context.Background(), zone, input)

		if err != nil {
			t.Fatalf("SetRecords failed: %v", err)
		}

		if len(ret) != 1 {
			t.Fatalf("should have returned 1 record got %d", len(ret))
		}

		t.Logf("testing return record types are not of type libdns.RR")
		testReturnTypes(t, ret)

		curr, err := provider.GetRecords(context.Background(), zone)

		if err != nil {
			t.Fatalf("GetRecords failed: %v", err)
		}

		t.Log("current records in zone:")
		printRecords(t, curr, nil, " ")

		var shouldNotExist = original[:2]

		t.Log("testing if following records are removed")
		printRecords(t, shouldNotExist, nil, " ")

		for invalid, record := range helper.RecordIterator(&shouldNotExist) {
			if helper.IsInList(&record, &curr) {
				t.Log("")
				printRecords(t, curr, *invalid, " ")
				t.Fatal("invalid records returned")
			}
		}

		var shouldExist = append(original[2:], input[0])
		t.Log("testing if following records are present")
		printRecords(t, shouldExist, nil, " ")

		for invalid, record := range helper.RecordIterator(&shouldExist) {
			if false == helper.IsInList(&record, &curr) {
				t.Log("")
				printRecords(t, curr, *invalid, " ")
				t.Fatal("invalid records returned")
			}
		}
	}
}

func testRecordsSetExample2(t *testing.T, provider Provider, zones []string) {
	var name = "LibDNS.test.set.records"

	var original = []libdns.Record{
		libdns.Address{Name: "alpha." + name, IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "alpha." + name, IP: netip.MustParseAddr("2001:db8::2")},
		libdns.Address{Name: "beta." + name, IP: netip.MustParseAddr("2001:db8::3")},
		libdns.Address{Name: "beta." + name, IP: netip.MustParseAddr("2001:db8::4")},
	}

	var input = []libdns.Record{
		libdns.Address{Name: "alpha." + name, IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "alpha." + name, IP: netip.MustParseAddr("2001:db8::2")},
		libdns.Address{Name: "alpha." + name, IP: netip.MustParseAddr("2001:db8::5")},
	}

	t.Log("will test the following example:")
	t.Log("")
	t.Log("//	;; Original zone")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::1")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::2")
	t.Log("//	beta.example.com.  3600 IN AAAA 2001:db8::3")
	t.Log("//	beta.example.com.  3600 IN AAAA 2001:db8::4")
	t.Log("//")
	t.Log("//	;; Input")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::1")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::2")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::5")
	t.Log("//")
	t.Log("//	;; Resultant zone")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::1")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::2")
	t.Log("//	alpha.example.com. 3600 IN AAAA 2001:db8::5")
	t.Log("//	beta.example.com.  3600 IN AAAA 2001:db8::3")
	t.Log("//	beta.example.com.  3600 IN AAAA 2001:db8::4")

	for _, zone := range zones {
		out, err := provider.AppendRecords(context.Background(), zone, original)

		if err != nil {
			t.Fatalf("AppendRecords failed: %v", err)
		}

		t.Logf("records appended to zone \"%s\":", zone)
		printRecords(t, out, nil, "✓ ")

		// make sure we delete all records even on failure
		defer provider.DeleteRecords(context.Background(), zone, []libdns.Record{
			libdns.RR{Name: "alpha." + name, Type: "AAAA"},
			libdns.RR{Name: "beta." + name, Type: "AAAA"},
		})

		t.Logf("set record \"%s %s %s %s\":", input[0].RR().Name, input[0].RR().TTL, input[0].RR().Type, input[0].RR().Data)
		ret, err := provider.SetRecords(context.Background(), zone, input)

		if err != nil {
			t.Fatalf("SetRecords failed: %v", err)
		}

		if len(ret) != 1 {
			t.Fatalf("should have returned 1 record got %d", len(ret))
		}

		t.Logf("testing return record types are not of type libdns.RR")
		testReturnTypes(t, ret)

		curr, err := provider.GetRecords(context.Background(), zone)

		if err != nil {
			t.Fatalf("GetRecords failed: %v", err)
		}

		t.Log("current records in zone:")
		printRecords(t, curr, nil, " ")

		var shouldExist = append(original, input[2])

		t.Log("testing if following records are present")
		printRecords(t, shouldExist, nil, " ")

		for invalid, record := range helper.RecordIterator(&shouldExist) {
			if false == helper.IsInList(&record, &curr) {
				t.Log("")
				printRecords(t, curr, *invalid, " ")
				t.Fatal("AppendRecords returned unexpected records")
			}
		}
	}
}

func testDeleteRecords(t *testing.T, provider Provider, zones []string) {

	var name = "LibDNS.test.rm.records"

	for _, zone := range zones {

		var records = make([]libdns.Record, 0)

		for i := 1; i <= 10; i++ {
			records = append(records,
				libdns.Address{Name: name, IP: netip.MustParseAddr(fmt.Sprintf("2001:db8::%d", i))},
				libdns.Address{Name: name, IP: netip.MustParseAddr(fmt.Sprintf("127.0.0.%d", i))},
			)
		}

		out, err := provider.SetRecords(context.Background(), zone, records)

		if err != nil {
			t.Fatalf("SetRecords failed: %v", err)
		}

		t.Logf("set test records for zone \"%s\":", zone)
		printRecords(t, out, nil, "✓ ")

		var toRemove = records[:5]

		removed, err := provider.DeleteRecords(context.Background(), zone, toRemove)

		if err != nil {
			t.Fatalf("DeleteRecords failed: %v", err)
		}

		t.Logf("testing return record types are not of type libdns.RR")
		testReturnTypes(t, removed)

		for _, x := range helper.RecordIterator(&removed) {
			if false == helper.IsInList(&x, &toRemove) {
				t.Log("")
				printRecords(t, toRemove, x, " ")
				t.Fatal("returned unexpected records")
			}
		}

		t.Log("deleted records:")
		printRecords(t, removed, nil, "✓ ")

		t.Log("checking removed records against records in zone")
		curr, err := provider.GetRecords(context.Background(), zone)

		if err != nil {
			t.Fatalf("GetRecords failed: %v", err)
		}

		for _, x := range helper.RecordIterator(&toRemove) {
			if helper.IsInList(&x, &curr) {
				t.Log("")
				printRecords(t, curr, x, " ")
				t.Fatal("returned unexpected records")
			}
		}

		t.Log("try to delete records based name only")

		removed, err = provider.DeleteRecords(context.Background(), zone, []libdns.Record{
			libdns.RR{Name: name},
		})

		if err != nil {
			t.Fatalf("DeleteRecords failed: %v", err)
		}

		t.Log("deleted records:")
		printRecords(t, removed, nil, "✓ ")

		if len(removed) != 15 {
			t.Fatalf("returned invalid count of records: expecting 15 got %d", len(removed))
		}
	}
}
