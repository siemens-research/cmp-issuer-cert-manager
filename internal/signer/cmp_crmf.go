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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"time"
)

/*
CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
*/
type CertReqMessages = []CertReqMsg

/*
	CertReqMsg ::= SEQUENCE {
		certReq   CertRequest,
		popo       ProofOfPossession  OPTIONAL, -- content depends upon key type
		regInfo   SEQUENCE SIZE(1..MAX) of AttributeTypeAndValue OPTIONAL
	}
*/
type CertReqMsg struct {
	CertReq CertRequest
	Popo    ProofOfPossession            `asn1:"optional"` // ,omitempty
	RegInfo []pkix.AttributeTypeAndValue `asn1:"optional,omitempty"`
}

func MakeCertReqMsgFromP10(id int, csr *x509.CertificateRequest, regInfo []pkix.AttributeTypeAndValue) *CertReqMsg {
	return &CertReqMsg{
		CertReq: MakeCertRequestFromP10CSR(id, csr),
		Popo:    ChoiceConvert(raVerified, ASN1_NULL),
		RegInfo: regInfo,
	}
}

func MakeCertReqMsg(id int, subject pkix.Name, privKey *crypto.PrivateKey, extensions []pkix.Extension,
	controls []pkix.AttributeTypeAndValue, regInfo []pkix.AttributeTypeAndValue) (crm CertReqMsg, err error) {

	var publicKey crypto.PublicKey
	if privKey != nil {
		publicKey = GetPublicKey(*privKey)
	}
	req := MakeCertRequest(id, subject, &publicKey, extensions, controls)

	popo := ChoiceConvert(raVerified, ASN1_NULL)
	if privKey != nil {
		signKey, ok := (*privKey).(crypto.Signer)
		if !ok {
			err = fmt.Errorf("cannot use private key of type %T for signature-based POPO", privKey)
			return
		}
		popo, err = MakeSignaturePOPO(signKey, req)
		if err != nil {
			return
		}
	} else {
		log.Printf("no private key for POPO, using RaVerified\n")
	}

	crm = CertReqMsg{
		CertReq: req,
		Popo:    popo,
		RegInfo: regInfo,
	}
	return
}

/*
	CertRequest ::= SEQUENCE {
		certReqId     INTEGER,        -- ID for matching request and reply
		certTemplate  CertTemplate, --Selected fields of cert to be issued
		controls      Controls OPTIONAL } -- Attributes affecting issuance

Controls ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
*/
type CertRequest struct {
	CertReqID    int
	CertTemplate CertTemplate
	Controls     []Control `asn1:"optional,omitempty"`
}

func MakeCertRequestFromP10CSR(id int, csr *x509.CertificateRequest) (req CertRequest) {
	var ok = false
	var pub crypto.PublicKey

	switch csr.PublicKey.(type) {
	case *rsa.PublicKey:
		pub, ok = csr.PublicKey.(*rsa.PublicKey)
	case *ecdsa.PublicKey:
		pub, ok = csr.PublicKey.(*ecdsa.PublicKey)
	case ed25519.PublicKey:
		pub, ok = csr.PublicKey.(ed25519.PublicKey)
	default:
		log.Panicf("unsupported public key type in CSR: %T", csr.PublicKey)
	}
	if !ok {
		log.Panicf("failed to extract public key from CSR: %T", csr.PublicKey)
	}
	req = CertRequest{
		CertReqID: id,
		CertTemplate: CertTemplate{
			Subject:    Name{RDNSequence: ConvertToUTF8StringRDNSequence(csr.Subject.ToRDNSequence())},
			PublicKey:  MakeSubjectPublicKeyInfo(&pub),
			Extensions: csr.Extensions,
		},
	}
	return
}

func MakeCertRequest(id int, subject pkix.Name, publicKey *crypto.PublicKey,
	extensions []pkix.Extension, controls []pkix.AttributeTypeAndValue) (req CertRequest) {
	req = CertRequest{
		CertReqID: id,
		CertTemplate: CertTemplate{
			// Version: 2,
			Subject:    Name{RDNSequence: ConvertToUTF8StringRDNSequence(subject.ToRDNSequence())},
			Extensions: extensions,
		},
		Controls: controls,
	}
	if publicKey != nil {
		req.CertTemplate.PublicKey = MakeSubjectPublicKeyInfo(publicKey)
	}
	return
}

type Control = pkix.AttributeTypeAndValue

/*
id-regCtrl-oldCertID OBJECT IDENTIFIER ::= { id-regCtrl 5 } -- with syntax:

OldCertId ::= CertId

	CertId ::= SEQUENCE {
		issuer           GeneralName,
		serialNumber     INTEGER }
*/
type OldCertID struct {
	Issuer       GeneralName
	SerialNumber *big.Int
}

var oidRegCtrlOldCertID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 5}

/*
	CertTemplate ::= SEQUENCE {
		version      [0] Version               OPTIONAL,
		serialNumber [1] INTEGER               OPTIONAL,
		signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
		issuer       [3] Name                  OPTIONAL,
		validity     [4] OptionalValidity      OPTIONAL,
		subject      [5] Name                  OPTIONAL,
		publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
		issuerUID    [7] UniqueIdentifier      OPTIONAL,
		subjectUID   [8] UniqueIdentifier      OPTIONAL,
		extensions   [9] Extensions            OPTIONAL }
*/
type CertTemplate struct {
	Version      int                      `asn1:"tag:0,optional"`           // SHOULD be absent, otherwise MUST be 2
	SerialNumber *big.Int                 `asn1:"tag:1,optional,omitempty"` // MUST be absent
	SigningAlg   pkix.AlgorithmIdentifier `asn1:"tag:2,optional,omitempty"` // MUST be absent
	Issuer       Name                     `asn1:"tag:3,optional,omitempty"`
	Validity     Validity                 `asn1:"tag:4,optional,omitempty"`
	Subject      Name                     `asn1:"tag:5,optional,omitempty"`
	PublicKey    SubjectPublicKeyInfo     `asn1:"tag:6,optional,omitempty"`
	IssuerUID    asn1.BitString           `asn1:"tag:7,optional,omitempty"` // SHOULD be absent
	SubjectUID   asn1.BitString           `asn1:"tag:8,optional,omitempty"` // SHOULD be absent
	Extensions   []pkix.Extension         `asn1:"tag:9,optional,omitempty"`
}

/*
	OptionalValidity ::= SEQUENCE {
		notBefore  [0] Time OPTIONAL,
		notAfter   [1] Time OPTIONAL } --at least one must be present
*/
type Validity struct {
	NotBefore time.Time `asn1:"tag:0,optional"`
	NotAfter  time.Time `asn1:"tag:1,optional"`
}

/*
	CRMFTime ::= CHOICE {
		utcTime        UTCTime,
		generalTime    GeneralizedTime }
*/
type Time struct {
	UTCTime         time.Time `asn1:"utc"`
	GeneralizedTime time.Time `asn1:"generalized"`
}

/*
	ProofOfPossession ::= CHOICE {
		raVerified        [0] NULL,
			 -- used if the RA has already verified that the requester is in
			 -- possession of the private key
		signature         [1] POPOSigningKey,
		keyEncipherment   [2] POPOPrivKey,
		keyAgreement      [3] POPOPrivKey }
*/
type ProofOfPossession = asn1.RawValue

const (
	raVerified = iota
	signature
	keyEncipherment
	keyAgreement
)

/*
	POPOSigningKey ::= SEQUENCE {
		poposkInput           [0] POPOSigningKeyInput OPTIONAL,
		algorithmIdentifier   AlgorithmIdentifier,
		signature             BIT STRING }
*/
type POPOSigningKey struct {
	PoposkInput         []byte `asn1:"tag:0,optional,omitempty"` // TODO if needed
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	Signature           asn1.BitString
}

func MakeSignaturePOPO(privKey crypto.Signer, req CertRequest) (popo asn1.RawValue, err error) {
	algId, err := getSignAlgorithmIdentifier(privKey)
	if err != nil {
		return
	}
	reqBytes, err := asn1.Marshal(req)
	if err != nil {
		log.Panicf("error marshaling CertRequest: %v", err)
	}
	sigBytes, err := SignData(reqBytes, algId, privKey)
	if err != nil {
		return
	}

	sigBits := asn1.BitString{Bytes: sigBytes, BitLength: len(sigBytes) * 8}
	poposk := POPOSigningKey{AlgorithmIdentifier: algId, Signature: sigBits}

	return ChoiceConvertEx(signature, poposk, true), nil
}
