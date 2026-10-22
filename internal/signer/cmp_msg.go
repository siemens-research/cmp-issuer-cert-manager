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
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"os"
)

type PKIProtection struct{ Bytes asn1.BitString }

/*
	PKIMessage ::= SEQUENCE {
		header           PKIHeader,
		body             PKIBody,
		protection   [0] PKIProtection OPTIONAL,
		extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL
	}
*/
type PKIMessage struct {
	// cannot use lower-case field names, which whould lead to "asn1: structure error: struct contains unexported fields"
	RawHeader asn1.RawValue
	RawBody   asn1.RawValue

	Protection    PKIProtection    `asn1:"optional,tag:0,omitempty"`
	RawExtraCerts []RawCertificate `asn1:"explicit,optional,tag:1,omitempty"`

	/*
		The following fields are not to be included in the DER encoding.
		Must place them at the end of the strucuture to prevent parsing errors.
	*/
	Header     PKIHeader        `asn1:"optional,omitempty"`
	Body       PKIBody          `asn1:"optional,omitempty"`
	ExtraCerts []CMPCertificate `asn1:"optional,omitempty"`
}

func MarshalPKIBody(body *PKIBody) asn1.RawValue {
	if body == nil {
		log.Panicf("PKIBody is nil")
	}
	if body.CertReq != nil {
		return ChoiceConvert(body.Type, []CertReqMsg{*body.CertReq})
	} else if body.P10CR != nil {
		return MakeChoice(PKCS10CertificationRequest, true, body.P10CR.Raw)
	} else if body.CertConf != nil {
		return ChoiceConvert(CertificateConfirm, CertConfirmContent{*body.CertConf})
	} else {
		panic(fmt.Errorf("unsupported type marshalling PKIBody"))
	}
}

func (trans *Transaction) MakePKIMessage(body *PKIBody, implicitConfirm bool, secret string,
	privateKey crypto.PrivateKey, certChain []*x509.Certificate) (
	msg PKIMessage, err error) {
	var header PKIHeader
	header, err = MakePKIHeader(trans, implicitConfirm, secret, certChain)
	if err != nil {
		err = fmt.Errorf("error creating PKIHeader structure: %w", err)
		return
	}

	msg, err = msgProtect(header, body, secret, privateKey, certChain)
	if err != nil {
		err = fmt.Errorf("error protecting PKIMessage structure: %w", err)
	}

	return
}

func (msg *PKIMessage) BodyTypeName() string {
	return BodyType2String(msg.RawBody.Tag)
}

func (msg *PKIMessage) Marshal() (asDER []byte, err error) {
	asDER, err = asn1.Marshal(*msg)
	if err != nil {
		err = fmt.Errorf("error marshalling %s PKIMessage structure: %w", msg.BodyTypeName(), err)
	}
	return
}

func parseCMPCertificates(list []RawCertificate, name, desc_postfix string) (certs []CMPCertificate, err error) {
	certs = make([]*x509.Certificate, len(list))
	for i, rawCert := range list {
		bytes := rawCert.FullBytes
		if dumpdebug {
			cmplogConfig.mutex.Lock()
			defer cmplogConfig.mutex.Unlock()
			path := fmt.Sprintf("log/%s/", cmplogConfig.serverName)
			err := os.WriteFile(path+"rsp"+fmt.Sprint(cmplogConfig.dumpFileIndex)+"-"+name+".crt", bytes, 0644)
			if err != nil {
				log.Printf("error writing certificate %d to file: %v", i, err)
			}
		}
		certs[i], err = x509.ParseCertificate(bytes)
		if err != nil {
			err = fmt.Errorf("error parsing certificate %d in %s%s: %w", i, name, desc_postfix, err)
			return
		}
	}
	return
}

func ParsePKIMessage(derEncoded []byte) (msg PKIMessage, err error) {
	_, err = asn1.Unmarshal(derEncoded, &msg)
	if err != nil {
		err = fmt.Errorf("error parsing PKIMessage structure: %w", err)
		return
	}
	desc := msg.BodyTypeName() + " message"
	body := msg.RawBody

	_, err = asn1.Unmarshal(msg.RawHeader.FullBytes, &msg.Header)
	if err != nil {
		err = fmt.Errorf("%w for header of %s", err, desc)
		// Extra check for debugging, as EJBCA leaves the NULL value for implicitConfirm in AttributeTypeAndValue:
		if len(msg.Header.GeneralInfo) > 0 {
			_, err1 := asn1.Marshal(msg.Header.GeneralInfo[0])
			if err1 != nil {
				err = fmt.Errorf("error marshaling first GeneralInfo element of core %s PKIMessage for protection: %w",
					msg.BodyTypeName(), err1)
			}
		}
		return
	}

	msg.Body.Type = body.Tag
	switch body.Tag {
	case InitializationResponse, CertificationResponse, KeyUpdateResponse, CrossCertResponse:
		var crm CertRepMessage
		_, err = asn1.Unmarshal(body.Bytes, &crm)
		if err != nil {
			err = fmt.Errorf("%w for CertRepMessage of %s", err, desc)
			return
		}
		if len(crm.Response) != 1 {
			err = fmt.Errorf("unexpected number of CertResponse items in %s: %v", desc, len(crm.Response))
			return
		}

		msg.Body.CertRep = &CertRep{
			Status: crm.Response[0].Status,
		}
		msg.Body.CertRep.CAPubs, err = parseCMPCertificates(crm.CaPubs, "caPubs", " of "+desc)
		if err != nil {
			err = fmt.Errorf("%w of %s", err, desc)
			return
		}

		if crm.Response[0].Status.Status == Accepted {
			msg.Body.CertRep.Cert, err = extractCertificate(crm.Response[0].CertifiedKeyPair.CertOrEncCert, desc)
			if err != nil {
				return
			}
		}
	case PKIConfirmation:
		msg.Body.PkiConf = &PKIConfirmContent{ASN1_Null{}}

	case ErrorMessage:
		var errorContent ErrorMsgContent
		_, err = asn1.Unmarshal(body.Bytes, &errorContent)
		if err != nil {
			err = fmt.Errorf("%w for ErrorMsgContent of %s", err, desc)
			return
		}
		msg.Body.Error = &errorContent
	}

	msg.ExtraCerts, err = parseCMPCertificates(msg.RawExtraCerts, "extraCerts", " of "+desc)
	if err != nil {
		err = fmt.Errorf("%w for extraCerts of %v message", err, desc)
		return
	}
	return
}
