package main

import (
	"os"
	"testing"

	"github.com/libdns/enum"
	"github.com/libdns/libdns/libdnstest"
)

func TestEnumProvider(t *testing.T) {
	apiKey := os.Getenv("ENUM_API_KEY")
	projectID := os.Getenv("ENUM_PROJECT_ID")
	zone := os.Getenv("ENUM_TEST_ZONE")

	if apiKey == "" || projectID == "" || zone == "" {
		t.Skip("ENUM_API_KEY, ENUM_PROJECT_ID and ENUM_TEST_ZONE must be set")
	}

	suite := libdnstest.NewTestSuite(&enum.Provider{APIKey: apiKey, ProjectID: projectID}, zone)
	suite.SkipRRTypes = map[string]bool{
		"HTTPS": true,
		"SVCB":  true,
		"NS":    true,
	}

	suite.RunTests(t)
}
