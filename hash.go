package aidgo

import (
	"crypto/sha256"
	"fmt"
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
	for k, v := range cert.Claims {
		str += k + fmt.Sprintf("%v", v)
	}
	for k, v := range cert.Setting {
		str += k + fmt.Sprintf("%v", v)
	}
	for k, v := range cert.VerifyOptions {
		str += k + fmt.Sprintf("%v", v)
	}
	return str
}

func hashString(str string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(str)))
}
