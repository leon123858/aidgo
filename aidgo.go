package aidgo

import "github.com/google/uuid"

type Verifier interface {
	// cert related
	saveCert(cert AidCert) error
	clearCert(cert AidCert) error
	getCert(aid uuid.UUID) (AidCert, error)
	verifyCert(aid uuid.UUID, option string, msg interface{}, generator VerifyGenerator) error
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
	// p2p aid, option
	p2p func(uuid.UUID, interface{}) error
	// server aid, option, ServerInfo
	server func(uuid.UUID, interface{}, ServerInfo) error
	// blockchain aid, option, ContractInfo
	blockchain func(uuid.UUID, interface{}, ContractInfo) error
	// full aid, option, claims, ServerInfo, ContractInfo
	full func(uuid.UUID, interface{}, map[string]interface{}, ServerInfo, ContractInfo) error
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

func (v *VerifierImpl) verifyCert(aid uuid.UUID, option string, msg interface{}, generator VerifyGenerator) error {
	cert, err := v.getCert(aid)
	if err != nil {
		return err
	}
	if cert.VerifyOptions[option] == nil {
		return NewBadRequestError("Option not found")
	}
	switch cert.CertType {
	case P2p:
		return generator.p2p(aid, msg)
	case Server:
		return generator.server(aid, msg, cert.ServerInfo)
	case Blockchain:
		return generator.blockchain(aid, msg, cert.ContractInfo)
	case Full:
		return generator.full(aid, msg, cert.Claims, cert.ServerInfo, cert.ContractInfo)
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
