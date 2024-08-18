package aidgo

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strconv"
	"time"
)

func DefaultRsaVerifyAlgo(original, signatureBase64, publicKeyPem string) error {
	// base64 to []byte
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return err
	}
	// publicKey to rsa.PublicKey
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return NewInternalServerError("failed to decode PEM block containing public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return NewInternalServerError("failed to parse public key")
	}
	// verify the signature
	hashed := sha256.Sum256([]byte(original))
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return err
	}
	return nil
}

func DefaultTimestampTimeoutAlgo(timestampStr string, timeoutSec ...int64) error {
	var maxTimeDiff int64 = 60
	if len(timeoutSec) > 0 {
		maxTimeDiff = timeoutSec[0]
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	timeDiff := now - timestamp/1000

	if timeDiff > maxTimeDiff || timeDiff < -maxTimeDiff {
		return NewBadRequestError("timestamp expired")
	}

	return nil
}
