package aidgo

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_cert2String(t *testing.T) {
	cert := AidCert{
		Aid:      uuid.MustParse("10db9410-4bcd-4056-bad0-3142c643e9ee"),
		CertType: P2p,
		ContractInfo: ContractInfo{
			ContractAddress: "test",
			BlockChainUrl:   "test",
		},
		ServerInfo: ServerInfo{
			ServerAddress: "test",
			Sign:          "test",
		},
		Claims: map[string]interface{}{
			"test": "test",
		},
		Setting: map[string]interface{}{
			"test": "test",
		},
		VerifyOptions: map[string]interface{}{
			"test": "test",
		},
	}
	assert.Equal(t, "10db9410-4bcd-4056-bad0-3142c643e9eetesttesttesttest\"test\"test\"test\"test\"test\"", cert2String(&cert))
}
