package aidgo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"
)

// Mock for VerifyGenerator
type MockVerifyGenerator struct {
	mock.Mock
}

func (m *MockVerifyGenerator) p2p(aid uuid.UUID, option string, msg interface{}, certOption interface{}) error {
	args := m.Called(aid, option, msg, certOption)
	return args.Error(0)
}

func (m *MockVerifyGenerator) server(aid uuid.UUID, option string, msg interface{}, certOption interface{}, info ServerInfo) error {
	args := m.Called(aid, option, msg, certOption, info)
	return args.Error(0)
}

func (m *MockVerifyGenerator) blockchain(aid uuid.UUID, option string, msg interface{}, certOption interface{}, info ContractInfo) error {
	args := m.Called(aid, option, msg, certOption, info)
	return args.Error(0)
}

func (m *MockVerifyGenerator) full(aid uuid.UUID, option string, msg interface{}, certOption interface{}, claims map[string]interface{}, serverInfo ServerInfo, contractInfo ContractInfo) error {
	args := m.Called(aid, option, msg, certOption, claims, serverInfo, contractInfo)
	return args.Error(0)
}

func TestVerifierImpl_VerifyCert(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	cert := AidCert{
		Aid:      aid,
		CertType: P2p,
		VerifyOptions: map[string]interface{}{
			"test": true,
		},
	}
	_ = v.saveCert(cert)

	mockGenerator := new(MockVerifyGenerator)
	mockGenerator.On("p2p", aid, "test", "message", true).Return(nil)

	err := v.verifyCert(aid, "test", "message", &VerifyGenerator{P2p: mockGenerator.p2p})
	assert.NoError(t, err, "verifyCert should not return an error for valid cert")

	mockGenerator.AssertCalled(t, "p2p", aid, "test", "message", true)
}

func TestNewVerifier(t *testing.T) {
	v := NewVerifier()
	assert.NotNil(t, v, "NewVerifier should return a non-nil Verifier")
}

func TestVerifierImpl_SaveAndGetCert(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	cert := AidCert{Aid: aid, CertType: P2p}

	err := v.saveCert(cert)
	assert.NoError(t, err, "saveCert should not return an error")

	savedCert, err := v.getCert(aid)
	assert.NoError(t, err, "getCert should not return an error")
	assert.Equal(t, cert, savedCert, "getCert should return the saved cert")
}

func TestVerifierImpl_ClearCert(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	cert := AidCert{Aid: aid, CertType: P2p}

	_ = v.saveCert(cert)
	err := v.clearCert(cert)
	assert.NoError(t, err, "clearCert should not return an error")

	_, err = v.getCert(aid)
	assert.Error(t, err, "getCert should return an error after clearing")
	assert.IsType(t, NewNotFoundError("test"), err, "Error should be of type NotFoundError")
}

func TestVerifierImpl_CacheAndGetRecord(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	record := AidRecord{Aid: aid, Option: "test", TimeStamp: time.Now(), Msg: "test message"}

	err := v.cacheRecord(record)
	assert.NoError(t, err, "cacheRecord should not return an error")

	savedRecord, err := v.getRecord(aid)
	assert.NoError(t, err, "getRecord should not return an error")
	assert.Equal(t, record, savedRecord, "getRecord should return the cached record")
}

func TestVerifierImpl_ClearRecord(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	record := AidRecord{Aid: aid, Option: "test", TimeStamp: time.Now(), Msg: "test message"}

	_ = v.cacheRecord(record)
	err := v.clearRecord(aid)
	assert.NoError(t, err, "clearRecord should not return an error")

	_, err = v.getRecord(aid)
	assert.Error(t, err, "getRecord should return an error after clearing")
	assert.IsType(t, NewNotFoundError("not found"), err, "Error should be of type NotFoundError")
}

func TestVerifierImpl_SaveAndGetData(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	data := AidData{Aid: aid, Data: map[string]interface{}{"test": "data"}}

	err := v.saveData(data)
	assert.NoError(t, err, "saveData should not return an error")

	savedData, err := v.getData(aid)
	assert.NoError(t, err, "getData should not return an error")
	assert.Equal(t, data, savedData, "getData should return the saved data")
}

func TestVerifierImpl_ClearData(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	data := AidData{Aid: aid, Data: map[string]interface{}{"test": "data"}}

	_ = v.saveData(data)
	err := v.clearData(aid)
	assert.NoError(t, err, "clearData should not return an error")

	_, err = v.getData(aid)
	assert.Error(t, err, "getData should return an error after clearing")
	assert.IsType(t, err, err, "Error should be of type NotFoundError")
}

func TestVerifierImpl_VerifyCertWithRSA(t *testing.T) {
	// front-end
	aid := uuid.New()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err, "Failed to generate RSA key pair")

	publicKey := &privateKey.PublicKey
	pemPublicKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})
	assert.NotNil(t, pemPublicKey, "Failed to encode public key to PEM")
	pemPublicKeyBase64 := base64.StdEncoding.EncodeToString(pemPublicKey)

	cert := AidCert{
		Aid:      aid,
		CertType: P2p,
		VerifyOptions: map[string]interface{}{
			"rsa": map[string]string{
				"publicKey": pemPublicKeyBase64,
			},
		},
		Claims: make(map[string]interface{}),
	}
	assert.NoError(t, err, "Failed to save cert")

	originalString := "Hello World!"
	byteOriginalString := []byte(originalString)
	hashedMsg := sha256.Sum256(byteOriginalString)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedMsg[:])
	assert.NoError(t, err, "Failed to sign message")

	// base64 encode signature
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	req := []string{originalString, signatureBase64}

	// back-end
	v := NewVerifier()
	err = v.saveCert(cert)
	verifyGenerator := NewVerifyGenerator()
	verifyGenerator.P2p = func(aid uuid.UUID, option string, msg interface{}, certOption interface{}) error {
		assert.Equal(t, "rsa", option)
		// msg is a ["Hello World!", "signature"]
		originalString := msg.([]string)[0]
		signatureBase64 := msg.([]string)[1]
		// certOption is a map[string]string{"publicKey": "base64 encoded public key"}
		publicKeyBase64 := certOption.(map[string]string)["publicKey"]
		// base64 to []byte
		signature, err := base64.StdEncoding.DecodeString(signatureBase64)
		assert.NoError(t, err, "Failed to decode signature")
		publicKeyByte, err := base64.StdEncoding.DecodeString(publicKeyBase64)
		assert.NoError(t, err, "Failed to decode public key")
		// publicKey to rsa.PublicKey
		block, _ := pem.Decode(publicKeyByte)
		assert.NotNil(t, block, "Failed to decode PEM block")
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		assert.NoError(t, err, "Failed to parse public key")
		// verify the signature
		hashedMsg := sha256.Sum256([]byte(originalString))
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedMsg[:], signature)
		return err
	}

	result := v.verifyCert(aid, "rsa", req, verifyGenerator)
	assert.NoError(t, result, "Failed to verify signature")

	// test invalid signature
	req[0] = "Hello World"
	result = v.verifyCert(aid, "rsa", req, verifyGenerator)
	assert.Error(t, result, "Failed to verify invalid signature")
}
