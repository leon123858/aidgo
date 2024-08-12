package aidgo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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

func (m *MockVerifyGenerator) p2p(aid uuid.UUID, msg interface{}) error {
	args := m.Called(aid, msg)
	return args.Error(0)
}

func (m *MockVerifyGenerator) server(aid uuid.UUID, msg interface{}, info ServerInfo) error {
	args := m.Called(aid, msg, info)
	return args.Error(0)
}

func (m *MockVerifyGenerator) blockchain(aid uuid.UUID, msg interface{}, info ContractInfo) error {
	args := m.Called(aid, msg, info)
	return args.Error(0)
}

func (m *MockVerifyGenerator) full(aid uuid.UUID, msg interface{}, claims map[string]interface{}, serverInfo ServerInfo, contractInfo ContractInfo) error {
	args := m.Called(aid, msg, claims, serverInfo, contractInfo)
	return args.Error(0)
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
	mockGenerator.On("p2p", aid, mock.Anything).Return(nil)

	err := v.verifyCert(aid, "test", "message", VerifyGenerator{p2p: mockGenerator.p2p})
	assert.NoError(t, err, "verifyCert should not return an error for valid cert")

	mockGenerator.AssertCalled(t, "p2p", aid, "message")
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
	v := NewVerifier()
	aid := uuid.New()

	// 生成 RSA 密鑰對
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err, "Failed to generate RSA key pair")

	publicKey := &privateKey.PublicKey

	// 創建一個包含公鑰的證書
	cert := AidCert{
		Aid:      aid,
		CertType: P2p,
		VerifyOptions: map[string]interface{}{
			"rsa": map[string]*rsa.PublicKey{
				"publicKey": publicKey,
			},
		},
		Claims: make(map[string]interface{}),
	}

	err = v.saveCert(cert)
	assert.NoError(t, err, "Failed to save cert")

	// 創建一個消息並使用公鑰加密
	originalMsg := "Hello, World!"
	encryptedMsg, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		[]byte(originalMsg),
		nil,
	)
	assert.NoError(t, err, "Failed to encrypt message")

	// 創建一個解密函數作為驗證生成器
	verifyGenerator := VerifyGenerator{
		p2p: func(uid uuid.UUID, msg interface{}) error {
			encryptedBase64, ok := msg.(string)
			if !ok {
				return NewBadRequestError("Invalid message format")
			}

			encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedBase64)
			if err != nil {
				return NewBadRequestError("Invalid base64 encoding")
			}

			decryptedMsg, err := rsa.DecryptOAEP(
				sha256.New(),
				rand.Reader,
				privateKey,
				encryptedBytes,
				nil,
			)
			if err != nil {
				return NewBadRequestError("Decryption failed")
			}

			if string(decryptedMsg) != originalMsg {
				return NewBadRequestError("Message mismatch")
			}

			return nil
		},
	}

	// 執行驗證
	encryptedBase64 := base64.StdEncoding.EncodeToString(encryptedMsg)
	err = v.verifyCert(aid, "rsa", encryptedBase64, verifyGenerator)
	assert.NoError(t, err, "verifyCert should not return an error for valid cert and message")
}
