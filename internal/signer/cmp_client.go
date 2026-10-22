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
	"crypto/x509/pkix"
	"fmt"
)

type CMPClientFlags struct {
	preferCRMF, // use crmf in CR or IR, otherwise use P10CR
	preferCR, // cr if preferCR, otherwise ir
	acceptNonMatchingNoncesInErrors, // wrong transactionID and recipNonce
	acceptNonProtectedNegativeOrPKIConf, // unprotected or wrongly protected pkiConf or negative PKIStatusInfo
	acceptKeyUsageNoDigitalSignature,
	acceptNewCertValidationFailure, // for instance, due to missing trusted or untrusted CA certs
	disableConfirm,
	requestImplicitConfirm bool
}

type CMPClient struct {
	sharedSecret string
	newKey,
	privateKey crypto.PrivateKey
	certChain,
	trustedCerts,
	untrustedCerts []*x509.Certificate
	flags       CMPClientFlags
	recipientDN pkix.RDNSequence
	transport   TransportService
}

type CmpSigner struct {
	cmpClient *CMPClient
}

type CmpHealthChecker struct {
	transport TransportService
}

func (trans *Transaction) exchangeConfirm(cert *x509.Certificate, report error) (err error) {
	/*
	   certHash    OCTET STRING,
	   -- the hash of the certificate, using the same hash algorithm
	   -- as is used to create and verify the certificate signature
	*/
	hashAlg, err := hashFuncBySigAlg(cert.SignatureAlgorithm)
	if err != nil {
		return
	}
	if hashAlg == crypto.Hash(0) {
		if cert.SignatureAlgorithm != x509.SignatureAlgorithm(x509.Ed25519) {
			err = fmt.Errorf("unsupported signature algorithm with built-in hashing: %v", cert.SignatureAlgorithm)
			return
		}
		hashAlg = crypto.SHA512 // Ed25519 uses SHA-512 - https://datatracker.ietf.org/doc/html/rfc9481#section-3.3
	}

	certStatus := MakeCertStatus(Hash(cert.Raw, hashAlg), report)
	_, err = trans.performRequest(&PKIBody{CertConf: &certStatus}, false, PKIConfirmation)
	return
}

func (trans *Transaction) exchangeCertReq(pkcs10_csr *x509.CertificateRequest) (
	publicKey crypto.PublicKey, resp PKIMessage, err error) {

	trans.senderDN = pkcs10_csr.Subject.ToRDNSequence()
	trans.publicKey = pkcs10_csr.PublicKey
	var msgBody PKIBody
	if trans.cmpClient.flags.preferCRMF {
		certReqMsg := MakeCertReqMsgFromP10(0, pkcs10_csr, nil)
		var requestBodyType int
		if trans.cmpClient.flags.preferCR {
			requestBodyType = CertificationRequest
		} else {
			requestBodyType = InitializationRequest
		}
		msgBody = PKIBody{CertReq: certReqMsg, Type: requestBodyType}
	} else {
		msgBody = PKIBody{P10CR: pkcs10_csr, Type: PKCS10CertificationRequest}
	}
	var responseBodyType int
	if trans.cmpClient.flags.preferCRMF {
		if trans.cmpClient.flags.preferCR {
			responseBodyType = CertificationResponse
		} else {
			responseBodyType = InitializationResponse
		}
	} else {
		responseBodyType = CertificationResponse
	}

	resp, err = trans.performRequest(&msgBody, trans.cmpClient.flags.requestImplicitConfirm, responseBodyType)
	return
}

/*
Perform certification request transaction, using
* p10cr (and ignore newKey) if pkcs10_csr is not nil, otherwise
* kur if subject is nil, otherwise
* cr if preferCR, otherwise ir.
Include X.509 extensions if exts is not nil.
Request implicit confirmation if global requestImplicitConfirm is true;
do not confirm if implicit confirmation was granted or global disableConfirm is true
*/
func (trans *Transaction) RequestCertificate(pkcs10_csr *x509.CertificateRequest) (
	certificate *x509.Certificate, chain []*x509.Certificate, err error) {

	cmpClient := trans.cmpClient

	publicKey, resp, err1 := trans.exchangeCertReq(pkcs10_csr)
	if err1 != nil {
		err = err1
		return
	}

	desc := fmt.Sprintf("%v message", resp.BodyTypeName())
	certRep := resp.Body.CertRep
	if len(certRep.CAPubs) > 0 {
		if isKnownMACbased(resp.Header.ProtectionAlg.Algorithm) { // TODO generalize to any MAC-based protection
			addCAcerts(certRep.CAPubs, false, &cmpClient.trustedCerts, "trust anchors")
		} else {
			warn.Println("Ignoring caPubs of ", desc, "as it is unclear how to authorize the sender")
		}
	}

	err = checkCertResponse(certRep, desc)
	if err != nil {
		return
	}
	certificate = certRep.Cert

	eq, ok := publicKey.(interface{ Equal(crypto.PublicKey) bool })

	if !ok || !eq.Equal(certificate.PublicKey) {
		err1 = fmt.Errorf("certificate public key in %s does not match key provided in CSR", desc)
	} else {
		chains, err1 := ValidateCert(certificate, "newly enrolled", "", anyEKU, cmpClient.trustedCerts, cmpClient.untrustedCerts, resp.ExtraCerts)
		if err1 != nil && !cmpClient.flags.acceptNewCertValidationFailure {
			err1 = fmt.Errorf("failure validating newly enrolled certificate in %s: %w", desc, err1)
		} else {
			if debug {
				PrintCert("\nCertificate obtained via "+desc, certificate)
			}
			if len(chains) == 0 {
				chain = []*x509.Certificate{certificate}
			} else {
				chain = chains[0]
			}
		}
	}
	if !cmpClient.flags.disableConfirm && !resp.Header.HasImplicitConfirm() {
		err = trans.exchangeConfirm(certificate, err1)
	}
	return
}
