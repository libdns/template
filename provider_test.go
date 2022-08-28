// Package dinahosting implements a DNS record management client compatible
// with the libdns interfaces for Dinahosting (https://es.dinahosting.com/api).
package dinahosting

import (
	"context"
	"reflect"
	"testing"

	"github.com/libdns/libdns"
)

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

// This test assumes your test zone only has 1 A record.
// Please modify record.Value with your actual IP value.
func TestProvider_GetRecords(t *testing.T) {
	type fields struct {
		Username string
		Password string
	}
	type args struct {
		ctx  context.Context
		zone string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []libdns.Record
		wantErr bool
	}{
		{
			name: "Test A record exists",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
			},
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "A",
					Name:     "@",
					Value:    ip,
					TTL:      0,
					Priority: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "Test auth error",
			fields: fields{
				Username: "wrongUser",
				Password: "wrongPass",
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				Username: tt.fields.Username,
				Password: tt.fields.Password,
			}
			got, err := p.GetRecords(tt.args.ctx, tt.args.zone)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provider.GetRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.GetRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_AppendRecords(t *testing.T) {
	type fields struct {
		Username string
		Password string
	}
	type args struct {
		ctx     context.Context
		zone    string
		records []libdns.Record
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []libdns.Record
		wantErr bool
	}{
		{
			name: "Test create A record",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
				records: []libdns.Record{
					{
						ID:       "",
						Type:     "A",
						Name:     "test",
						Value:    "1.1.1.1",
						TTL:      0,
						Priority: 0,
					},
				},
			},
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "A",
					Name:     "test",
					Value:    "1.1.1.1",
					TTL:      0,
					Priority: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "Test error when same A record exists",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
				records: []libdns.Record{
					{
						ID:       "",
						Type:     "A",
						Name:     "test",
						Value:    "1.1.1.1",
						TTL:      0,
						Priority: 0,
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Test create TXT record",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
				records: []libdns.Record{
					{
						ID:       "",
						Type:     "TXT",
						Name:     "test",
						Value:    "2.2.2.2",
						TTL:      0,
						Priority: 0,
					},
				},
			},
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "TXT",
					Name:     "test",
					Value:    "2.2.2.2",
					TTL:      0,
					Priority: 0,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				Username: tt.fields.Username,
				Password: tt.fields.Password,
			}
			got, err := p.AppendRecords(tt.args.ctx, tt.args.zone, tt.args.records)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provider.AppendRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.AppendRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_SetRecords(t *testing.T) {
	type fields struct {
		Username string
		Password string
	}
	type args struct {
		ctx     context.Context
		zone    string
		records []libdns.Record
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []libdns.Record
		wantErr bool
	}{
		{
			name: "Test update A record",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
				records: []libdns.Record{
					{
						ID:       "",
						Type:     "A",
						Name:     "test",
						Value:    "2.2.2.2",
						TTL:      0,
						Priority: 0,
					},
				},
			},
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "A",
					Name:     "test",
					Value:    "2.2.2.2",
					TTL:      0,
					Priority: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "Test create TXT record",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
				records: []libdns.Record{
					{
						ID:       "",
						Type:     "TXT",
						Name:     "test",
						Value:    "3.3.3.3",
						TTL:      0,
						Priority: 0,
					},
				},
			},
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "TXT",
					Name:     "test",
					Value:    "3.3.3.3",
					TTL:      0,
					Priority: 0,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				Username: tt.fields.Username,
				Password: tt.fields.Password,
			}
			got, err := p.SetRecords(tt.args.ctx, tt.args.zone, tt.args.records)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provider.SetRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.SetRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_DeleteRecords(t *testing.T) {

	type fields struct {
		Username string
		Password string
	}
	type args struct {
		ctx     context.Context
		zone    string
		records []libdns.Record
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []libdns.Record
		wantErr bool
	}{
		{
			name: "Test deletion of A record",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
				records: []libdns.Record{
					{
						ID:       "",
						Type:     "A",
						Name:     "test",
						Value:    "2.2.2.2",
						TTL:      0,
						Priority: 0,
					},
				},
			},
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "A",
					Name:     "test",
					Value:    "2.2.2.2",
					TTL:      0,
					Priority: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "Test deletion of TXT record",
			fields: fields{
				Username: username,
				Password: password,
			},
			args: args{
				ctx:  context.Background(),
				zone: zone,
				records: []libdns.Record{
					{
						ID:       "",
						Type:     "TXT",
						Name:     "test",
						Value:    "2.2.2.2",
						TTL:      0,
						Priority: 0,
					},
					{
						ID:       "",
						Type:     "TXT",
						Name:     "test",
						Value:    "3.3.3.3",
						TTL:      0,
						Priority: 0,
					},
				},
			},
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "TXT",
					Name:     "test",
					Value:    "2.2.2.2",
					TTL:      0,
					Priority: 0,
				},
				{
					ID:       "",
					Type:     "TXT",
					Name:     "test",
					Value:    "3.3.3.3",
					TTL:      0,
					Priority: 0,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				Username: tt.fields.Username,
				Password: tt.fields.Password,
			}
			got, err := p.DeleteRecords(tt.args.ctx, tt.args.zone, tt.args.records)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provider.DeleteRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.DeleteRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}
