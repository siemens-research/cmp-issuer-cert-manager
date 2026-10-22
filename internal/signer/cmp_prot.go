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
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Calculate the protection bits of msgCore, which must contain RawHeader and RawBody, and only these two.
func (msgCore *PKIMessage) messageProtection(protAlg pkix.AlgorithmIdentifier, secret string,
	privKey crypto.PrivateKey, publicKey crypto.PublicKey, msgProtection []byte) (prot PKIProtection, err error) {

	messsageByteString, err := asn1.Marshal(*msgCore)
	if err != nil {
		err = fmt.Errorf("error marshaling SEQUENCE of core %s PKIMessage for protection: %w", msgCore.BodyTypeName(), err)
		return
	}

	protectionByteArray := []byte{}

	macBased := isKnownMACbased(protAlg.Algorithm)
	if macBased {
		if secret == "" {
			err = errors.New("missing shared secret for MAC-based protection")
			return
		}
		protectionByteArray, err = HMAC(messsageByteString, protAlg, secret)
	} else if privKey != nil {
		signKey, ok := privKey.(crypto.Signer)
		if !ok {
			err = fmt.Errorf("cannot use private key of type %T for signature-based message protection", privKey)
			return
		}
		protectionByteArray, err = SignData(messsageByteString, protAlg, signKey)
	} else if publicKey != nil {
		err = VerifySignature(messsageByteString, msgProtection, protAlg, publicKey)
		// protectionByteArray is not used in this case
	} else {
		err = errors.New("no private key for signing or public key for verification provided")
	}
	if err != nil {
		return
	}

	return PKIProtection{Bytes: asn1.BitString{Bytes: protectionByteArray,
		BitLength: len(protectionByteArray) * 8}}, nil
}

func msgProtect(hdr PKIHeader, body *PKIBody, secret string,
	privKey crypto.PrivateKey, certChain []*x509.Certificate) (msg PKIMessage, err error) {
	macBased := secret != ""

	if macBased {
		hdr.ProtectionAlg, err = getMACAlgorithmIdentifier(oidPBM, oidHMACWithSHA1)
		// On HMAC-SHA256, Insta Demo CA responds with PKIFailureInfo: badDataFormat; StatusString: "ASN.1 decoding error"
		// TODO: possibly use also PBMAC1 if supported
	} else {
		if privKey == nil {
			err = fmt.Errorf("missing secret or private key for protecting message")
			return
		}
		hdr.ProtectionAlg, err = getSignAlgorithmIdentifier(privKey)
	}
	if err != nil {
		return
	}

	hdrBytes, err1 := asn1.Marshal(hdr)
	if err1 != nil {
		err = fmt.Errorf("error marshaling PKIHeader: %w", err1)
		return
	}
	msg = PKIMessage{
		RawHeader: asn1.RawValue{FullBytes: hdrBytes},
		RawBody:   MarshalPKIBody(body),
	}
	msg.Protection, err = msg.messageProtection(hdr.ProtectionAlg, secret, privKey, nil, nil)
	if err != nil {
		return
	}
	if !macBased {
		if len(certChain) < 1 {
			err = errors.New("missing protection certificate in certChain")
			return
		}
		if !keysMatch(privKey, certChain[0].PublicKey) {
			err = errors.New("signer private key does not match first certificate in chain")
			return
		}

		// marshal extraCerts
		msg.RawExtraCerts = make([]RawCertificate, len(certChain))
		for i, cert := range certChain {
			msg.RawExtraCerts[i] = RawCertificate{FullBytes: cert.Raw}
		}
	}
	return
}

func (client *CMPClient) checkProtection(msg *PKIMessage, requestProt pkix.AlgorithmIdentifier, acceptKeyUsageNoDigitalSignature bool) (err error) {

	hdr := msg.Header
	protAlg := hdr.ProtectionAlg
	if protAlg.Algorithm == nil {
		err = fmt.Errorf("missing protection")
		return
	}

	macBasedProtection := isKnownMACbased(protAlg.Algorithm)
	if requestProt.Algorithm != nil {
		macBasedRequest := isKnownMACbased(requestProt.Algorithm)
		if macBasedProtection != macBasedRequest {
			warn.Println("response protection algorithm '" + protAlgString(protAlg) +
				"' does not match request protection algorithm '" + protAlgString(requestProt) + "'")
		}
	}

	var pubKey crypto.PublicKey
	if !macBasedProtection { // assuming signature-based protection
		extraCerts := msg.ExtraCerts
		if len(client.trustedCerts) == 0 {
			err = fmt.Errorf("missing trust anchor(s) for verifying signature-based protection")
			return
		}
		if len(extraCerts) == 0 {
			err = fmt.Errorf("missing protection certificate in extraCerts")
			return
		}

		protectionCert := extraCerts[0] // assuming first extra cert is the CMP signer cert of the sender
		if protectionCert.KeyUsage != 0 && protectionCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			msg := "key usage '" + KeyUsageString(protectionCert.KeyUsage) + " of protection certificate does not allow digitalSignature"
			if acceptKeyUsageNoDigitalSignature {
				warn.Println(msg)
			} else {
				err = errors.New(msg)
				return
			}
		}

		err = checkEqualDirNames(hdr.Sender, "sender",
			protectionCert.Subject.String(), "subject of protection certificate in extraCerts")
		if err != nil {
			return err
		}

		otherCerts := extraCerts[1:]
		pubKey = protectionCert.PublicKey

		_, err = ValidateCert(protectionCert, "protection", "", anyEKU, client.trustedCerts, client.untrustedCerts, otherCerts)
		if err != nil {
			err = fmt.Errorf("failure validating protection certificate: %w", err)
			return
		}
	}

	msgCore := PKIMessage{
		RawHeader: msg.RawHeader,
		RawBody:   msg.RawBody,
	}
	prot, err := msgCore.messageProtection(protAlg, client.sharedSecret, nil, pubKey, msg.Protection.Bytes.Bytes)
	if err != nil {
		return
	}
	if macBasedProtection && !bytes.Equal(prot.Bytes.Bytes, msg.Protection.Bytes.Bytes) {
		err = fmt.Errorf("wrong MAC-based protection")
	}
	return
}
