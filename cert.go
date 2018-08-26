package main

import (
	"crypto"
	"errors"
	"crypto/elliptic"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"
	"math/big"
	"io/ioutil"
)

type cert struct {
	privateKey crypto.PrivateKey
	publicKey *x509.Certificate
}

type keys struct{
	privateKey string
	publicKey string
	issuingCA string
}

func (ca *cert) setupCA(privateKeyPath string, publicKeyPath string) error {
	var err error
	var certerr error

	caBuf, err := ioutil.ReadFile(publicKeyPath)
	publicKeyPem, _ := pem.Decode(caBuf)
	ca.publicKey, err = x509.ParseCertificate(publicKeyPem.Bytes)

	caPrivBuf, err := ioutil.ReadFile(privateKeyPath)
	caPrivBufDer, _ := pem.Decode(caPrivBuf)

	if err == nil {
		ca.privateKey, certerr = x509.ParsePKCS1PrivateKey(caPrivBufDer.Bytes)
	} else {
		return err
	}
	if certerr != nil {
		ca.privateKey, certerr = x509.ParseECPrivateKey(caPrivBufDer.Bytes)
	}
	if certerr != nil {
		return certerr
	}
		return err
}

func (ca *cert) genCertificate(issueTime time.Time, expireTime time.Time, commonName string) (keys, error) {

	var k keys
	var err error

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
		},
		NotBefore:             issueTime,
		NotAfter:              expireTime,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	priv, err := genPrivateKey("P256")
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.publicKey, publicKey(priv), ca.privateKey)

	k.privateKey = string(pem.EncodeToMemory(pemBlockForKey(priv)))
	k.publicKey = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	k.issuingCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.publicKey.Raw}))

	return k, err
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func genPrivateKey(keyType string) (crypto.PrivateKey, error){
	var priv crypto.PrivateKey
	var err error

	switch keyType {
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "RSA4096":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case "RSA2048":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		err = errors.New("Unknown key type: " + keyType)
	}
	return priv, err
}

