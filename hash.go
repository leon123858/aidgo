package aidgo

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

func (cert *AidCert) Hash(strategy ...func(cert *AidCert) string) string {
	if len(strategy) > 0 {
		return strategy[0](cert)
	}
	return cert.DefaultHashStrategy()
}

func (cert *AidCert) DefaultHashStrategy() string {
	return hashString(cert2String(cert))
}

func cert2String(cert *AidCert) string {
	str := cert.Aid.String()
	str += cert.ContractInfo.ContractAddress
	str += cert.ContractInfo.BlockChainUrl
	str += cert.ServerInfo.ServerAddress
	str += *sortedPrintMap(cert.Claims)
	str += *sortedPrintMap(cert.Setting)
	str += *sortedPrintMap(cert.VerifyOptions)
	return str
}

func sortedPrintMap(m map[string]interface{}) *string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// sort keys
	sort.Strings(keys)
	// print map
	str := ""
	for v := range keys {
		str += keys[v] + fmt.Sprintf("%v", m[keys[v]])
	}
	return &str
}

func hashString(str string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(str)))
}
