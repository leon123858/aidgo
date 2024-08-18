package aidgo

import "github.com/google/uuid"

type Verifier interface {
	// SaveCert cert related
	SaveCert(cert AidCert) error
	ClearCert(cert AidCert) error
	GetCert(aid uuid.UUID) (AidCert, error)
	VerifyCert(aid uuid.UUID, option string, msg interface{}, generator *VerifyGenerator) error
	// CacheRecord record related
	CacheRecord(record AidRecord) error
	GetRecord(aid uuid.UUID) (AidRecord, error)
	ClearRecord(aid uuid.UUID) error
	// SaveData data related
	SaveData(data AidData) error
	GetData(aid uuid.UUID) (AidData, error)
	ClearData(aid uuid.UUID) error
}

type VerifyGenerator struct {
	// p2p aid, option, msg, certOption
	P2p func(uuid.UUID, string, interface{}, interface{}) error
	// server aid, option, msg, AidCert, ServerInfo
	Server func(uuid.UUID, string, interface{}, AidCert, ServerInfo) error
	// blockchain aid, option, msg, AidCert, ContractInfo
	Blockchain func(uuid.UUID, string, interface{}, AidCert, ContractInfo) error
	// full aid, option, msg, AidCert, claims, ServerInfo, ContractInfo
	Full func(uuid.UUID, string, interface{}, AidCert, map[string]interface{}, ServerInfo, ContractInfo) error
}

func NewVerifyGenerator() *VerifyGenerator {
	return &VerifyGenerator{
		P2p: func(aid uuid.UUID, option string, msg interface{}, certOption interface{}) error {
			return NewNotImplementedError("p2p not implemented")
		},
		Server: func(aid uuid.UUID, option string, msg interface{}, cert AidCert, info ServerInfo) error {
			return NewNotImplementedError("server not implemented")
		},
		Blockchain: func(aid uuid.UUID, option string, msg interface{}, cert AidCert, info ContractInfo) error {
			return NewNotImplementedError("blockchain not implemented")
		},
		Full: func(aid uuid.UUID, option string, msg interface{}, cert AidCert, claims map[string]interface{}, serverInfo ServerInfo, contractInfo ContractInfo) error {
			return NewNotImplementedError("full not implemented")
		},
	}
}

type VerifierImpl struct {
	Storage
	Cache
}

func NewVerifier() *VerifierImpl {
	return &VerifierImpl{
		Storage: Storage{
			Certs: make(map[uuid.UUID]AidCert),
			Data:  make(map[uuid.UUID]AidData),
		},
		Cache: Cache{
			Records: make(map[uuid.UUID]AidRecord),
		},
	}
}

func (v *VerifierImpl) SaveCert(cert AidCert) error {
	v.Certs[cert.Aid] = cert
	return nil
}

func (v *VerifierImpl) ClearCert(cert AidCert) error {
	delete(v.Certs, cert.Aid)
	return nil
}

func (v *VerifierImpl) GetCert(aid uuid.UUID) (AidCert, error) {
	cert, ok := v.Certs[aid]
	if !ok {
		return AidCert{}, NewNotFoundError("Cert not found")
	}
	return cert, nil
}

func (v *VerifierImpl) VerifyCert(aid uuid.UUID, option string, msg interface{}, generator *VerifyGenerator) error {
	cert, err := v.GetCert(aid)
	if err != nil {
		return err
	}
	if cert.VerifyOptions[option] == nil {
		return NewBadRequestError("Option not found")
	}
	switch cert.CertType {
	case P2p:
		return generator.P2p(aid, option, msg, cert.VerifyOptions[option])
	case Server:
		return generator.Server(aid, option, msg, cert, cert.ServerInfo)
	case Blockchain:
		return generator.Blockchain(aid, option, msg, cert, cert.ContractInfo)
	case Full:

		return generator.Full(aid, option, msg, cert, cert.Claims, cert.ServerInfo, cert.ContractInfo)
	default:
		return NewNotImplementedError("CertType not implemented")
	}
}

func (v *VerifierImpl) CacheRecord(record AidRecord) error {
	v.Records[record.Aid] = record
	return nil
}

func (v *VerifierImpl) GetRecord(aid uuid.UUID) (AidRecord, error) {
	record, ok := v.Records[aid]
	if !ok {
		return AidRecord{}, NewNotFoundError("Record not found")
	}
	return record, nil
}

func (v *VerifierImpl) ClearRecord(aid uuid.UUID) error {
	delete(v.Records, aid)
	return nil
}

func (v *VerifierImpl) SaveData(data AidData) error {
	v.Data[data.Aid] = data
	return nil
}

func (v *VerifierImpl) GetData(aid uuid.UUID) (AidData, error) {
	data, ok := v.Data[aid]
	if !ok {
		return AidData{}, NewNotFoundError("Data not found")
	}
	return data, nil
}

func (v *VerifierImpl) ClearData(aid uuid.UUID) error {
	delete(v.Data, aid)
	return nil
}
