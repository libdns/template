package provider

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

// ListZones returns all available zones. Most APIs support listing of all managed
// domains, which can be used as zones.
//
// This function ensures that the returned domain names include a trailing dot
// to indicate the root zone.
func ListZones(ctx context.Context, mutex sync.Locker, client ZoneAwareClient) ([]libdns.Zone, error) {

	if unlock := lock(mutex); nil != unlock {
		defer unlock()
	}

	domains, err := client.Domains(ctx)

	if err != nil {
		return nil, err
	}

	var zones = make([]libdns.Zone, len(domains))

	for i, c := 0, len(domains); i < c; i++ {

		var name = domains[i].Name()

		if name[len(name)-1] != '.' {
			name += "."
		}

		zones[i] = libdns.Zone{
			Name: name,
		}
	}

	return zones, nil
}
