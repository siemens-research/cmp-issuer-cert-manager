/*
Copyright 2026 Siemens AG.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

/*
copied from https://github.com/golang/go/blob/master/src/crypto/x509/x509.go

OIDs for signature algorithms

	pkcs-1 OBJECT IDENTIFIER ::= {
		iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }

# RFC 3279 2.2.1 RSA Signature Algorithms

md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }

sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }

	dsaWithSha1 OBJECT IDENTIFIER ::= {
		iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }

# RFC 3279 2.2.3 ECDSA Signature Algorithm

	ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
		iso(1) member-body(2) us(840) ansi-x962(10045)
		signatures(4) ecdsa-with-SHA1(1)}

RFC 4055 5 PKCS #1 Version 1.5

sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }

sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }

sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }

# RFC 5758 3.1 DSA Signature Algorithms

	dsaWithSha256 OBJECT IDENTIFIER ::= {
		joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
		csor(3) algorithms(4) id-dsa-with-sha2(3) 2}

# RFC 5758 3.2 ECDSA Signature Algorithm

ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)

	us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }

ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)

	us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }

ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)

	us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }

# RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers

id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
*/
var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidSignatureMD5WithRSA  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA but id specified by ISO.
	// Microsoft's makecert.exe has been known to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMGF1                     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// copied and adapted from "crypto/x509/x509.go"
var signatureAlgorithmDetails = []struct {
	algo x509.SignatureAlgorithm
	name string
	oid  asn1.ObjectIdentifier
	// params  asn1.RawValue
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
	isRSAPSS   bool
}{
	{x509.MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA /*          asn1.NullRawValue,   */, x509.RSA, crypto.MD5, false},
	{x509.SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA /*       asn1.NullRawValue,   */, x509.RSA, crypto.SHA1, false},
	{x509.SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA /*    asn1.NullRawValue,   */, x509.RSA, crypto.SHA1, false},
	{x509.SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA /* asn1.NullRawValue,   */, x509.RSA, crypto.SHA256, false},
	{x509.SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA /* asn1.NullRawValue,   */, x509.RSA, crypto.SHA384, false},
	{x509.SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA /* asn1.NullRawValue,   */, x509.RSA, crypto.SHA512, false},
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS /*  pssParametersSHA256, */, x509.RSA, crypto.SHA256, true},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS /*  pssParametersSHA384, */, x509.RSA, crypto.SHA384, true},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS /*  pssParametersSHA512, */, x509.RSA, crypto.SHA512, true},
	{x509.DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1 /*       emptyRawValue,       */, x509.DSA, crypto.SHA1, false},
	{x509.DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256 /* emptyRawValue,       */, x509.DSA, crypto.SHA256, false},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1 /* emptyRawValue,       */, x509.ECDSA, crypto.SHA1, false},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256 /* emptyRawValue, */, x509.ECDSA, crypto.SHA256, false},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384 /* emptyRawValue, */, x509.ECDSA, crypto.SHA384, false},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512 /* emptyRawValue, */, x509.ECDSA, crypto.SHA512, false},
	{x509.PureEd25519, "Ed25519", oidSignatureEd25519 /* emptyRawValue, */, x509.Ed25519, crypto.Hash(0) /* no pre-hashing */, false},
}

/*
var emptyRawValue = asn1.RawValue{}

// DER encoded RSA PSS parameters for the
// SHA256, SHA384, and SHA512 hashes as defined in RFC 3447, Appendix A.2.3.
// The parameters contain the following values:
//   - hashAlgorithm contains the associated hash identifier with NULL parameters
//   - maskGenAlgorithm always contains the default mgf1SHA1 identifier
//   - saltLength contains the length of the associated hash
//   - trailerField always contains the default trailerFieldBC value
var (
	pssParametersSHA256 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 161,
		28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 162, 3, 2, 1, 32}}
	pssParametersSHA384 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 161,
		28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 162, 3, 2, 1, 48}}
	pssParametersSHA512 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 161,
		28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 162, 3, 2, 1, 64}}
)

func sigParams(sigOid asn1.ObjectIdentifier) asn1.RawValue {
	for _, details := range signatureAlgorithmDetails {
		if details.oid.Equal(sigOid) {
			return details.params
		}
	}
	return emptyRawValue // no parameters
}
*/

func pubAlg(sigOid asn1.ObjectIdentifier) (x509.PublicKeyAlgorithm, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.oid.Equal(sigOid) {
			return details.pubKeyAlgo, nil
		}
	}
	return x509.UnknownPublicKeyAlgorithm, fmt.Errorf("unsupported signature algorithm OID: %v", sigOid)
}

func hashFunc(sigOid asn1.ObjectIdentifier) (crypto.Hash, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.oid.Equal(sigOid) {
			return details.hash, nil
		}
	}
	return crypto.Hash(0), fmt.Errorf("unsupported signature algorithm OID: %v", sigOid)
}

func hashFuncBySigAlg(sigAlg x509.SignatureAlgorithm) (crypto.Hash, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == sigAlg {
			return details.hash, nil
		}
	}
	return crypto.Hash(0), fmt.Errorf("unsupported signature algorithm OID: %v", sigAlg)
}

// ReadPrivateKey loads a non-encrypted private key from a PEM file.
// With leading extra data like key parameters in the PEM file, fails with "asn1: structure error: tags don't match"
func ReadPrivateKey(filename string) (key crypto.PrivateKey, err error) {
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	key1, err1 := ParsePrivateKey(keyBytes)
	if err1 != nil {
		return key1, err1
	}
	return
}

func ParsePrivateKey(keyBytes []byte) (key crypto.PrivateKey, err error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block of private key")
	}
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key")
			}
		}
	}
	return
}

func WritePrivateKey(filename string, key crypto.PrivateKey) (err error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	keyFile, err1 := os.Create(filename)
	if err1 != nil {
		return fmt.Errorf("failed to create private key file %v: %v", filename, err1)
	}
	defer keyFile.Close()
	err = pem.Encode(keyFile, block)
	if err != nil {
		return fmt.Errorf("failed to write private key to file %v: %v", filename, err)
	}
	return
}

// ReadPublicKey loads a public key from a PEM file.
func ReadPublicKey(filename string) (crypto.PublicKey, error) { // unused
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block of public key file %v", filename)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func GetPublicKey(privateKey crypto.PrivateKey) crypto.PublicKey {
	// TODO: should work for all types of private keys
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		panic(fmt.Errorf("private key type does not support signing: %T", privateKey))
	}
	return signer.Public()
}

func keysMatch(privateKey any, publicKey any) bool {
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		pub, ok := publicKey.(*rsa.PublicKey)
		return ok && priv.PublicKey.Equal(pub)
	case *ecdsa.PrivateKey:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		return ok && priv.PublicKey.Equal(pub)
	case ed25519.PrivateKey:
		pub, ok := publicKey.(ed25519.PublicKey)
		return ok && priv.Public().(ed25519.PublicKey).Equal(pub)
	default:
		return false
	}
}

func GetHashOID(hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch hash {
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, nil
	case crypto.SHA224:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}, nil
	case crypto.SHA256:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, nil
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, nil
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm")
	}
}

/*
	RSASSA-PSS-params ::= SEQUENCE {
		hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
		maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
		saltLength         [2] INTEGER          DEFAULT 20,
		trailerField       [3] TrailerField     DEFAULT trailerFieldBC
*/
type PSSParameters struct { // TODO check if asn1 tags are correct
	HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional,omitempty"`
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:1,optional,omitempty"`
	SaltLength       int                      `asn1:"explicit,tag:2,optional,default:20,omitempty"`
	TrailerField     int                      `asn1:"explicit,tag:3,optional,default:1,omitempty"`
}

func marshalPSSOptions(pssOptions rsa.PSSOptions) (res asn1.RawValue, err error) { // TODO check if correct
	hashOID, err := GetHashOID(pssOptions.Hash)
	if err != nil {
		return
	}
	hashBytes, err := asn1.Marshal([]asn1.ObjectIdentifier{hashOID})
	if err != nil {
		return
	}

	pssParams := PSSParameters{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: ASN1_NULL,
		},
		MaskGenAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidMGF1,
			Parameters: asn1.RawValue{
				FullBytes: hashBytes,
			},
		},
		SaltLength:   pssOptions.SaltLength,
		TrailerField: 1,
	}

	paramsBytes, err := asn1.Marshal(pssParams)
	if err != nil {
		err = fmt.Errorf("error marshaling RSA-PSS parameters: %v", err)
	} else {
		res = asn1.RawValue{FullBytes: paramsBytes}
	}
	return
}

func signatureAlg(privateKey crypto.PrivateKey) asn1.ObjectIdentifier {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		// TODO: maybe make configurable
		return oidSignatureSHA256WithRSA // or oidSignatureRSAPSS
	case *ecdsa.PrivateKey:
		return oidSignatureECDSAWithSHA256 // TODO: maybe make hash algorithm configurable
	case ed25519.PrivateKey:
		return oidSignatureEd25519
	default:
		return nil
	}
}

func getSignAlgorithmIdentifier(privateKey crypto.PrivateKey) (algId pkix.AlgorithmIdentifier, err error) {
	if privateKey == nil {
		err = fmt.Errorf("missing private key")
		return
	}
	oid := signatureAlg(privateKey)
	if oid == nil {
		err = fmt.Errorf("unsupported signature private key type")
		return
	}

	algId = pkix.AlgorithmIdentifier{
		Algorithm: oid,
	}
	/*
		MUST set NULL parameters for RSASSA-PKCS1-v1_5, and MUST omit them for ECDSA and EdDSA,
		see https://datatracker.ietf.org/doc/html/rfc5754#section-3
		and https://datatracker.ietf.org/doc/html/rfc8419#section-2.4
	*/
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		algId.Parameters = ASN1_NULL
	}

	if oid.Equal(oidSignatureRSAPSS) {
		opts := rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
		// TODO: maybe make hash algorithm configurable
		optsBytes, err1 := marshalPSSOptions(opts)
		if err1 != nil {
			err = err1
			return
		}
		algId.Parameters = optsBytes // or, e.g., pssParametersSHA256
	}
	return
}

func handleSigHashing(alg pkix.AlgorithmIdentifier, data []byte, sigAlg x509.PublicKeyAlgorithm) (hashAlg crypto.Hash, tbs []byte, err error) {
	hashAlg, err = hashFunc(alg.Algorithm)
	tbs = data
	if hashAlg == crypto.Hash(0) {
		if sigAlg != x509.Ed25519 {
			err = fmt.Errorf("signature algorithm %v requires pre-hashing", sigAlg)
		}
	} else {
		if !hashAlg.Available() {
			err = fmt.Errorf("hash algorithm %v is not available", hashAlg)
		}
		tbs = Hash(data, hashAlg)
	}
	return
}

// variant of x509.signTBS, with consistency checks added
func SignData(data []byte, alg pkix.AlgorithmIdentifier, privKey crypto.Signer) (signature []byte, err error) {
	sigAlg, err := pubAlg(alg.Algorithm)
	if err != nil {
		return
	}
	hashAlg, tbs, err := handleSigHashing(alg, data, sigAlg)
	if err != nil {
		return
	}
	var signerOpts crypto.SignerOpts = hashAlg
	if alg.Algorithm.Equal(oidSignatureRSAPSS) {
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashAlg,
		}
	}
	signature, err = privKey.Sign(rand.Reader, tbs, signerOpts)
	if err != nil {
		return nil, err
	}

	// Verify our own signature for testing purposes, TODO consider removing for production
	if err := VerifySignature(data, signature, alg, privKey.Public()); err != nil {
		return nil, fmt.Errorf("x509: signature returned by signer is invalid: %w", err)
	}
	return
}

// partly inspired by x509.checkSignature()
func VerifySignature(data, signature []byte, alg pkix.AlgorithmIdentifier, publicKey crypto.PublicKey) error {
	sigAlg, err := pubAlg(alg.Algorithm)
	if err != nil {
		return err
	}
	hashAlg, tbs, err := handleSigHashing(alg, data, sigAlg)
	if err != nil {
		return err
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if sigAlg != x509.RSA {
			return fmt.Errorf("public key of type %T does not match signature algorithm: %v", key, sigAlg)
		}
		if alg.Algorithm.Equal(oidSignatureRSAPSS) {
			/*
				params := sigParams(alg.Algorithm)
				switch {
				case bytes.Equal(pssParams.FullBytes, pssParametersSHA256.FullBytes),
					bytes.Equal(pssParams.FullBytes, pssParametersSHA384.FullBytes),
					bytes.Equal(pssParams.FullBytes, pssParametersSHA512.FullBytes):
			*/
			var pssParams rsa.PSSOptions
			_, err := asn1.Unmarshal(alg.Parameters.FullBytes, &pssParams)
			if err != nil {
				return fmt.Errorf("error unmarshaling RSA-PSS parameters: %w", err)
			}
			return rsa.VerifyPSS(key, hashAlg, tbs, signature, &pssParams)
		} else {
			/*
				case bytes.Equal(params.FullBytes, asn1.NullRawValue.FullBytes):
			*/
			return rsa.VerifyPKCS1v15(key, hashAlg, tbs, signature)
			/*
				default:
					return fmt.Errorf("unsupported RSA signature parameters: %v", params)
			*/
		}
	case *ecdsa.PublicKey:
		if sigAlg != x509.ECDSA {
			return fmt.Errorf("public key of type %T does not match signature algorithm: %v", key, sigAlg)
		}
		if ecdsa.VerifyASN1(key, tbs, signature) {
			return nil
		} else {
			return fmt.Errorf("ECDSA signature verification failed")
		}
	case ed25519.PublicKey:
		if sigAlg != x509.Ed25519 {
			return fmt.Errorf("public key of type %T does not match signature algorithm: %v", key, sigAlg)
		}
		if ed25519.Verify(key, data, signature) {
			return nil
		} else {
			return fmt.Errorf("EdDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}
