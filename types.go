package aidgo

import (
	"github.com/google/uuid"
	"time"
)

type AidType string

const (
	P2p        AidType = "p2p"
	Server     AidType = "server"
	Blockchain AidType = "blockchain"
	Full       AidType = "full"
)

type ContractInfo struct {
	ContractAddress string
	BlockChainUrl   string
}

type ServerInfo struct {
	ServerAddress string
}

type AidCert struct {
	Aid      uuid.UUID
	CertType AidType
	ContractInfo
	ServerInfo
	Claims        map[string]interface{}
	Setting       map[string]interface{}
	VerifyOptions map[string]interface{}
}

type AidData struct {
	Aid  uuid.UUID
	Data map[string]interface{}
}

type Storage struct {
	Certs map[uuid.UUID]AidCert
	Data  map[uuid.UUID]AidData
}

type AidRecord struct {
	Aid       uuid.UUID
	Option    string
	TimeStamp time.Time
	Msg       interface{}
}

type Cache struct {
	Records map[uuid.UUID]AidRecord
}
