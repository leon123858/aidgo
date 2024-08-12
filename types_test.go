package aidgo

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestAidCert(t *testing.T) {
	aid := uuid.New()
	cert := AidCert{
		Aid:      aid,
		CertType: P2p,
		ContractInfo: ContractInfo{
			ContractAddress: "0x1234567890",
			BlockChainUrl:   "https://example.com",
		},
		ServerInfo: ServerInfo{
			ServerAddress: "192.168.1.1",
		},
		Claims:        make(map[string]interface{}),
		Setting:       make(map[string]interface{}),
		VerifyOptions: make(map[string]interface{}),
	}

	assertions := assert.New(t)
	assertions.Equal(aid, cert.Aid, "Aid should match")
	assertions.Equal(P2p, cert.CertType, "CertType should be P2p")
	assertions.Equal("0x1234567890", cert.ContractAddress, "ContractAddress should match")
	assertions.Equal("192.168.1.1", cert.ServerAddress, "ServerAddress should match")
}

func TestAidData(t *testing.T) {
	aid := uuid.New()
	data := AidData{
		Aid: aid,
		Data: map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		},
	}

	assertions := assert.New(t)
	assertions.Equal(aid, data.Aid, "Aid should match")
	assertions.Len(data.Data, 2, "Data should have 2 entries")
	assertions.Equal("value1", data.Data["key1"], "Data[\"key1\"] should be \"value1\"")
	assertions.Equal(42, data.Data["key2"], "Data[\"key2\"] should be 42")
}

func TestStorage(t *testing.T) {
	storage := Storage{
		Certs: make(map[uuid.UUID]AidCert),
		Data:  make(map[uuid.UUID]AidData),
	}

	aid1 := uuid.New()
	cert1 := AidCert{Aid: aid1, CertType: Server}
	storage.Certs[aid1] = cert1

	aid2 := uuid.New()
	data1 := AidData{Aid: aid2, Data: map[string]interface{}{"test": "data"}}
	storage.Data[aid2] = data1

	assertions := assert.New(t)
	assertions.Len(storage.Data, 1, "Data should have 1 entry")
	assertions.Equal(cert1, storage.Certs[aid1], "Cert in storage should match")
	assertions.Equal(data1, storage.Data[aid2], "Data in storage should match")
}

func TestCache(t *testing.T) {
	cache := Cache{
		Records: make(map[uuid.UUID]AidRecord),
	}

	aid := uuid.New()
	now := time.Now()
	record := AidRecord{
		Aid:       aid,
		Option:    "test",
		TimeStamp: now,
		Msg:       "Test message",
	}

	cache.Records[aid] = record

	assertions := assert.New(t)
	assertions.Len(cache.Records, 1, "Records should have 1 entry")
	assertions.Equal(record, cache.Records[aid], "Record in cache should match")
}
