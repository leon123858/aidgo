package aidgo

import "github.com/google/uuid"

type Verifier interface {
	// cert related
	saveCert(cert AidCert) error
	clearCert(cert AidCert) error
	getCert(aid uuid.UUID) (AidCert, error)
	verifyCert(aid uuid.UUID, option string, msg interface{}, generator *VerifyGenerator) error
	// record related
	cacheRecord(record AidRecord) error
	getRecord(aid uuid.UUID) (AidRecord, error)
	clearRecord(aid uuid.UUID) error
	// data related
	saveData(data AidData) error
	getData(aid uuid.UUID) (AidData, error)
	clearData(aid uuid.UUID) error
}

type VerifyGenerator struct {
	// p2p aid, option, msg, certOption
	P2p func(uuid.UUID, string, interface{}, interface{}) error
	// server aid, option, msg, certOption, ServerInfo
	Server func(uuid.UUID, string, interface{}, interface{}, ServerInfo) error
	// blockchain aid, option, msg, certOption, ContractInfo
	Blockchain func(uuid.UUID, string, interface{}, interface{}, ContractInfo) error
	// full aid, option, msg, certOption, claims, ServerInfo, ContractInfo
	Full func(uuid.UUID, string, interface{}, interface{}, map[string]interface{}, ServerInfo, ContractInfo) error
}

func NewVerifyGenerator() *VerifyGenerator {
	return &VerifyGenerator{
		P2p: func(aid uuid.UUID, option string, msg interface{}, certOption interface{}) error {
			return NewNotImplementedError("p2p not implemented")
		},
		Server: func(aid uuid.UUID, option string, msg interface{}, certOption interface{}, info ServerInfo) error {
			return NewNotImplementedError("server not implemented")
		},
		Blockchain: func(aid uuid.UUID, option string, msg interface{}, certOption interface{}, info ContractInfo) error {
			return NewNotImplementedError("blockchain not implemented")
		},
		Full: func(aid uuid.UUID, option string, msg interface{}, certOption interface{}, claims map[string]interface{}, serverInfo ServerInfo, contractInfo ContractInfo) error {
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

func (v *VerifierImpl) saveCert(cert AidCert) error {
	v.Certs[cert.Aid] = cert
	return nil
}

func (v *VerifierImpl) clearCert(cert AidCert) error {
	delete(v.Certs, cert.Aid)
	return nil
}

func (v *VerifierImpl) getCert(aid uuid.UUID) (AidCert, error) {
	cert, ok := v.Certs[aid]
	if !ok {
		return AidCert{}, NewNotFoundError("Cert not found")
	}
	return cert, nil
}

func (v *VerifierImpl) verifyCert(aid uuid.UUID, option string, msg interface{}, generator *VerifyGenerator) error {
	cert, err := v.getCert(aid)
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
		return generator.Server(aid, option, msg, cert.VerifyOptions[option], cert.ServerInfo)
	case Blockchain:
		return generator.Blockchain(aid, option, msg, cert.VerifyOptions[option], cert.ContractInfo)
	case Full:

		return generator.Full(aid, option, msg, cert.VerifyOptions[option], cert.Claims, cert.ServerInfo, cert.ContractInfo)
	default:
		return NewNotImplementedError("CertType not implemented")
	}
}

func (v *VerifierImpl) cacheRecord(record AidRecord) error {
	v.Records[record.Aid] = record
	return nil
}

func (v *VerifierImpl) getRecord(aid uuid.UUID) (AidRecord, error) {
	record, ok := v.Records[aid]
	if !ok {
		return AidRecord{}, NewNotFoundError("Record not found")
	}
	return record, nil
}

func (v *VerifierImpl) clearRecord(aid uuid.UUID) error {
	delete(v.Records, aid)
	return nil
}

func (v *VerifierImpl) saveData(data AidData) error {
	v.Data[data.Aid] = data
	return nil
}

func (v *VerifierImpl) getData(aid uuid.UUID) (AidData, error) {
	data, ok := v.Data[aid]
	if !ok {
		return AidData{}, NewNotFoundError("Data not found")
	}
	return data, nil
}

func (v *VerifierImpl) clearData(aid uuid.UUID) error {
	delete(v.Data, aid)
	return nil
}
