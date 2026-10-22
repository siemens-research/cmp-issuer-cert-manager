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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type RawCertificate = asn1.RawValue
type CMPCertificate = *x509.Certificate

type EncryptedKey = []byte

/*
	CertOrEncCert ::= CHOICE {
		certificate     [0] Certificate,
		encryptedCert   [1] EncryptedKey // was EncryptedValue in CMPv2
	}
*/
const (
	CertChoiceTag = iota
	EncryptedCertChoiceTag
)

type CertOrEncCert = asn1.RawValue

func extractCertificate(coe CertOrEncCert, desc string) (certificate *x509.Certificate, err error) {
	choiceBytes, err := GetChoiceBytes(coe, CertChoiceTag, "Certificate", "CertOrEncCert")
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate in %s: %w", desc, err)
	}
	certificate, err = x509.ParseCertificate(choiceBytes)
	if err != nil {
		err = fmt.Errorf("error parsing certificate in %s: %w", desc, err)
	}
	return
}

type PKIPublicationInfo = asn1.RawValue // deferred
/*
	CertifiedKeyPair ::= SEQUENCE {
		certOrEncCert       CertOrEncCert,
		privateKey      [0] EncryptedKey        OPTIONAL, // was EncryptedValue in CMPv2
		-- see [CRMF] for comment on encoding
		publicationInfo [1] PKIPublicationInfo  OPTIONAL
	}
*/
type CertifiedKeyPair struct {
	CertOrEncCert   CertOrEncCert
	PrivateKey      EncryptedKey       `asn1:"optional,omitempty"`
	PublicationInfo PKIPublicationInfo `asn1:"optional,omitempty"`
}

/*
	CertResponse ::= SEQUENCE {
		certReqId           INTEGER,
		status              PKIStatusInfo,
		certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
		rspInfo             OCTET STRING        OPTIONAL
		-- analogous to the id-regInfo-utf8Pairs string defined
		-- for regInfo in CertReqMsg [CRMF]
	}
*/
type CertResponse struct {
	CertReqID        int
	Status           PKIStatusInfo
	CertifiedKeyPair CertifiedKeyPair `asn1:"optional,omitempty"`
	RSPInfo          []byte           `asn1:"optional,omitempty"`
}

/*
	CertRepMessage ::= SEQUENCE {
		caPubs      [1] SEQUENCE SIZE (1..MAX) OF Certificate OPTIONAL,
		response    SEQUENCE OF CertResponse
	}
*/
type CertRepMessage struct {
	CaPubs   []RawCertificate `asn1:"explicit,optional,tag:1,omitempty"`
	Response []CertResponse
}

/*
	CertStatus ::= SEQUENCE {
		certHash    OCTET STRING,
		certReqId   INTEGER,
		statusInfo  PKIStatusInfo OPTIONAL
		hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL
	}
*/
type CertStatus struct {
	CertHash   []byte
	CertReqID  int
	StatusInfo PKIStatusInfo            `asn1:"optional,omitempty"`
	HashAlg    pkix.AlgorithmIdentifier `asn1:"optional,omitempty,tag:0"`
}

func MakeCertStatus(hash []byte, report error) CertStatus {
	certStatus := CertStatus{
		CertHash:  hash,
		CertReqID: 0, // also for p10cr transaction
		// StatusInfo not present means acceptance
		// HashAlg: ...	// optional, not needed so far
	}
	if report != nil {
		certStatus.StatusInfo = PKIStatusInfo{
			Status:       Rejection,
			StatusString: []UTF8String{String2UTF8String(report.Error())},
			FailInfo: asn1.BitString{
				Bytes:     []byte{0x01},
				BitLength: 8,
			}, // incorrectData; TODO generalize
		}
	}
	return certStatus
}

/*
PKIConfirmContent ::= NULL
*/
type PKIConfirmContent struct {
	NULL ASN1_Null
}

/*
CertConfirmContent ::= SEQUENCE OF CertStatus
*/
type CertConfirmContent []CertStatus

/*
	ErrorMsgContent ::= SEQUENCE {
		pKIStatusInfo          PKIStatusInfo,
		errorCode              INTEGER           OPTIONAL,
		errorDetails           PKIFreeText       OPTIONAL
		}
*/
type ErrorMsgContent struct {
	PKIStatusInfo PKIStatusInfo
	ErrorCode     int         `asn1:"optional,omitempty"`
	ErrorDetails  PKIFreeText `asn1:"optional,omitempty"`
}

/*
PKIBody ::= CHOICE {       -- message-specific body elements

		ir       [0]  CertReqMessages,        -- Initialization Request
		ip       [1]  CertRepMessage,         -- Initialization Response
		cr       [2]  CertReqMessages,        -- Certification Request
		cp       [3]  CertRepMessage,         -- Certification Response
		p10cr    [4]  CertificationRequest,   -- imported from [PKCS10]
		popdecc  [5]  POPODecKeyChallContent, -- POP Challenge
		popdecr  [6]  POPODecKeyRespContent,  -- POP Response
		kur      [7]  CertReqMessages,        -- Key Update Request
		kup      [8]  CertRepMessage,         -- Key Update Response
		krr      [9]  CertReqMessages,        -- Key Recovery Request
		krp      [10] KeyRecRepContent,       -- Key Recovery Response
		rr       [11] RevReqContent,          -- Revocation Request
		rp       [12] RevRepContent,          -- Revocation Response
		ccr      [13] CertReqMessages,        -- Cross-Cert. Request
		ccp      [14] CertRepMessage,         -- Cross-Cert. Response
		ckuann   [15] CAKeyUpdAnnContent,     -- CA Key Update Ann.
		cann     [16] CertAnnContent,         -- Certificate Ann.
		rann     [17] RevAnnContent,          -- Revocation Ann.
		crlann   [18] CRLAnnContent,          -- CRL Announcement
		pkiconf  [19] PKIConfirmContent,      -- Confirmation
		nested   [20] NestedMessageContent,   -- Nested Message
		genm     [21] GenMsgContent,          -- General Message
		genp     [22] GenRepContent,          -- General Response
		error    [23] ErrorMsgContent,        -- Error Message
		certConf [24] CertConfirmContent,     -- Certificate Confirm
		pollReq  [25] PollReqContent,         -- Polling Request
		pollRep  [26] PollRepContent          -- Polling Response
	}
*/
const (
	InitializationRequest = iota
	InitializationResponse
	CertificationRequest
	CertificationResponse
	PKCS10CertificationRequest
	POPChallenge
	POPResponse
	KeyUpdateRequest
	KeyUpdateResponse
	KeyRecoveryRequest
	KeyRecoveryResponse
	RevocationRequest
	RevocationResponse
	CrossCertRequest
	CrossCertResponse
	CAKeyUpdateAnnouncement
	CertificateAnnouncement
	RevocationAnnouncement
	CRLAnnouncement
	PKIConfirmation
	NestedMessage
	GeneralMessage
	GeneralResponse
	ErrorMessage
	CertificateConfirm
	PollingRequest
	PollingResponse
)

type CertRep = struct {
	CAPubs []CMPCertificate
	Cert   CMPCertificate
	Status PKIStatusInfo
}

type PKIBody = struct { // abstrct CMP message body
	Type    int
	CertReq *CertReqMsg
	P10CR   *x509.CertificateRequest
	CertRep *CertRep
	/*
		POPDecC  POPODecKeyChallContent `asn1:"explicit,optional,tag:5,omitempty"`
		POPDecR  POPODecKeyRespContent  `asn1:"explicit,optional,tag:6,omitempty"`
	*/
	/*
		KRR CertReqMessages `asn1:"explicit,optional,tag:9,omitempty"`

		KRP      KeyRecRepContent       `asn1:"explicit,optional,tag:10v"`
		RR       RevReqContent          `asn1:"explicit,optional,tag:11,omitempty"`
		RP       RevRepContent          `asn1:"explicit,optional,tag:12,omitempty"`
	*/
	/*
		CKUAnn   CAKeyUpdAnnContent     `asn1:"explicit,optional,tag:15,omitempty"`
		CAnn     CertAnnContent         `asn1:"explicit,optional,tag:16,omitempty"`
		RAnn     RevAnnContent          `asn1:"explicit,optional,tag:17,omitempty"`
		CRLAnn   CRLAnnContent          `asn1:"explicit,optional,tag:18,omitempty"`
	*/
	CertConf *CertStatus
	PkiConf  *PKIConfirmContent
	/*
		Nested   NestedMessageContent   `asn1:"explicit,optional,tag:20,omitempty"`
		GenM     GenMsgContent          `asn1:"explicit,optional,tag:21,omitempty"`
		GenP     GenRepContent          `asn1:"explicit,optional,tag:22,omitempty"`
	*/
	Error *ErrorMsgContent
	/*
		PollReq  PollReqContent         `asn1:"explicit,optional,tag:25,omitempty"`
		PollRep  PollRepContent         `asn1:"explicit,optional,tag:26,omitempty"`
	*/
}

func BodyType2String(bodyType int) string {
	switch bodyType {
	case InitializationRequest:
		return "Initialization Request"
	case InitializationResponse:
		return "Initialization Response"
	case CertificationRequest:
		return "Certification Request"
	case CertificationResponse:
		return "Certification Response"
	case PKCS10CertificationRequest:
		return "PKCS10 Certification Request"
	case POPChallenge:
		return "POP Challenge"
	case POPResponse:
		return "POP Response"
	case KeyUpdateRequest:
		return "Key Update Request"
	case KeyUpdateResponse:
		return "Key Update Response"
	case KeyRecoveryRequest:
		return "Key Recovery Request"
	case KeyRecoveryResponse:
		return "Key Recovery Response"
	case RevocationRequest:
		return "Revocation Request"
	case RevocationResponse:
		return "Revocation Response"
	case CrossCertRequest:
		return "Cross-Cert Request"
	case CrossCertResponse:
		return "Cross-Cert Response"
	case CAKeyUpdateAnnouncement:
		return "CA Key Update Announcement"
	case CertificateAnnouncement:
		return "Certificate Announcement"
	case RevocationAnnouncement:
		return "Revocation Announcement"
	case CRLAnnouncement:
		return "CRL Announcement"
	case PKIConfirmation:
		return "PKIConfirmation"
	case NestedMessage:
		return "Nested Message"
	case GeneralMessage:
		return "General Request"
	case GeneralResponse:
		return "General Response"
	case ErrorMessage:
		return "Error"
	case CertificateConfirm:
		return "Certificate Confirm"
	case PollingRequest:
		return "Polling Request"
	case PollingResponse:
		return "Polling Response"
	default:
		return "Unknown"
	}
}
