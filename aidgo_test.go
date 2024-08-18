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
	_ = v.SaveCert(cert)

	mockGenerator := new(MockVerifyGenerator)
	mockGenerator.On("p2p", aid, "test", "message", true).Return(nil)

	err := v.VerifyCert(aid, "test", "message", &VerifyGenerator{P2p: mockGenerator.p2p})
	assert.NoError(t, err, "VerifyCert should not return an error for valid cert")

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

	err := v.SaveCert(cert)
	assert.NoError(t, err, "SaveCert should not return an error")

	savedCert, err := v.GetCert(aid)
	assert.NoError(t, err, "GetCert should not return an error")
	assert.Equal(t, cert, savedCert, "GetCert should return the saved cert")
}

func TestVerifierImpl_ClearCert(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	cert := AidCert{Aid: aid, CertType: P2p}

	_ = v.SaveCert(cert)
	err := v.ClearCert(cert)
	assert.NoError(t, err, "ClearCert should not return an error")

	_, err = v.GetCert(aid)
	assert.Error(t, err, "GetCert should return an error after clearing")
	assert.IsType(t, NewNotFoundError("test"), err, "Error should be of type NotFoundError")
}

func TestVerifierImpl_CacheAndGetRecord(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	record := AidRecord{Aid: aid, Option: "test", TimeStamp: time.Now(), Msg: "test message"}

	err := v.CacheRecord(record)
	assert.NoError(t, err, "CacheRecord should not return an error")

	savedRecord, err := v.GetRecord(aid)
	assert.NoError(t, err, "GetRecord should not return an error")
	assert.Equal(t, record, savedRecord, "GetRecord should return the cached record")
}

func TestVerifierImpl_ClearRecord(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	record := AidRecord{Aid: aid, Option: "test", TimeStamp: time.Now(), Msg: "test message"}

	_ = v.CacheRecord(record)
	err := v.ClearRecord(aid)
	assert.NoError(t, err, "ClearRecord should not return an error")

	_, err = v.GetRecord(aid)
	assert.Error(t, err, "GetRecord should return an error after clearing")
	assert.IsType(t, NewNotFoundError("not found"), err, "Error should be of type NotFoundError")
}

func TestVerifierImpl_SaveAndGetData(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	data := AidData{Aid: aid, Data: map[string]interface{}{"test": "data"}}

	err := v.SaveData(data)
	assert.NoError(t, err, "SaveData should not return an error")

	savedData, err := v.GetData(aid)
	assert.NoError(t, err, "GetData should not return an error")
	assert.Equal(t, data, savedData, "GetData should return the saved data")
}

func TestVerifierImpl_ClearData(t *testing.T) {
	v := NewVerifier()
	aid := uuid.New()
	data := AidData{Aid: aid, Data: map[string]interface{}{"test": "data"}}

	_ = v.SaveData(data)
	err := v.ClearData(aid)
	assert.NoError(t, err, "ClearData should not return an error")

	_, err = v.GetData(aid)
	assert.Error(t, err, "GetData should return an error after clearing")
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
	err = v.SaveCert(cert)
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

	result := v.VerifyCert(aid, "rsa", req, verifyGenerator)
	assert.NoError(t, result, "Failed to verify signature")

	// test invalid signature
	req[0] = "Hello World"
	result = v.VerifyCert(aid, "rsa", req, verifyGenerator)
	assert.Error(t, result, "Failed to verify invalid signature")
}

func Test_HashCert(t *testing.T) {
	aid := "65236855-dec4-4fd7-ae74-8d4d79668e34"
	uid, err := uuid.Parse(aid)
	assert.NoError(t, err, "Failed to parse UUID")
	cert := AidCert{
		Aid: uid,
		ContractInfo: ContractInfo{
			ContractAddress: "0x1234567890",
			BlockChainUrl:   "http://localhost:8545",
		},
		ServerInfo: ServerInfo{
			ServerAddress: "127.0.0.1",
		},
		Claims: map[string]interface{}{
			"claim1": "value1",
			"claim2": 42,
		},
		Setting: map[string]interface{}{
			"setting1": "value1",
			"setting2": 42,
		},
		VerifyOptions: map[string]interface{}{
			"option1": "value1",
			"option2": 42,
		},
	}

	hash := cert.Hash()
	assert.NotEmpty(t, hash, "Hash should not be empty")
	assert.Equal(t, "e977dd1018de576a18132a412cfda8af6b4bdcbf4ba9cbbe0e56289c9372712f", hash, "Hash should be deterministic")
}
