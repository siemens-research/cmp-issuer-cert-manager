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
	"time"
)

const (
	CMP1999 = iota + 1
	CMP2000
	CMP2021
)

const nonceLen = 16

type Transaction struct {
	cmpClient *CMPClient
	senderDN,
	recipientDN pkix.RDNSequence
	transactionID,
	senderNonce,
	recipNonce []byte
	publicKey any
}

func initTransaction(cmpClient *CMPClient) (ret *Transaction, err error) {
	trans := Transaction{cmpClient: cmpClient, recipientDN: cmpClient.recipientDN}
	trans.transactionID, err = CreateRandom(nonceLen)
	if err != nil { // should not happen
		return nil, fmt.Errorf("error creating transactionID: %w", err)
	}
	return &trans, nil
}

func (trans *Transaction) updateNonces(hdr *PKIHeader) {
	trans.recipNonce = hdr.SenderNonce
}

/*
PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String

	-- text encoded as UTF-8 String [RFC3629] (note: each
	-- UTF8String MAY include an [RFC3066] language tag
	-- to indicate the language of the contained text
	-- see [RFC2482] for details)
*/
type PKIFreeText []UTF8String

var oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}

/*
	PKIHeader ::= SEQUENCE {
		pvno                INTEGER     { cmp1999(1), cmp2000(2) },
		sender              GeneralName,
		-- identifies the sender
		recipient           GeneralName,
		-- identifies the intended recipient
		messageTime     [0] GeneralizedTime         OPTIONAL,
		-- time of production of this message (used when sender
		-- believes that the transport will be "suitable"; i.e.,
		-- that the time will still be meaningful upon receipt)
		protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
		-- algorithm used for calculation of protection bits
		senderKID       [2] KeyIdentifier           OPTIONAL,
		recipKID        [3] KeyIdentifier           OPTIONAL,
		-- to identify specific keys used for protection
		transactionID   [4] OCTET STRING            OPTIONAL,
		-- identifies the transaction; i.e., this will be the same in
		-- corresponding request, response, certConf, and PKIConf
		-- messages
		senderNonce     [5] OCTET STRING            OPTIONAL,
		recipNonce      [6] OCTET STRING            OPTIONAL,
		-- nonces used to provide replay protection, senderNonce
		-- is inserted by the creator of this message; recipNonce
		-- is a nonce previously inserted in a related message by
		-- the intended recipient of this message
		freeText        [7] PKIFreeText             OPTIONAL,
		-- this may be used to indicate context-specific instructions
		-- (this field is intended for human consumption)
		generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
		                       InfoTypeAndValue     OPTIONAL
		-- this may be used to convey context-specific information
		-- (this field not primarily intended for human consumption)
		 }
*/
type PKIHeader struct {
	PVNO          int
	Sender        GeneralName
	Recipient     GeneralName
	MessageTime   time.Time                    `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg pkix.AlgorithmIdentifier     `asn1:"explicit,optional,tag:1,omitempty"`
	SenderKID     KeyIdentifier                `asn1:"explicit,optional,tag:2,omitempty"`
	RecipientKID  KeyIdentifier                `asn1:"explicit,optional,tag:3,omitempty"`
	TransactionID []byte                       `asn1:"explicit,optional,tag:4,omitempty"`
	SenderNonce   []byte                       `asn1:"explicit,optional,tag:5,omitempty"`
	RecipNonce    []byte                       `asn1:"explicit,optional,tag:6,omitempty"`
	FreeText      PKIFreeText                  `asn1:"explicit,optional,tag:7,omitempty"`
	GeneralInfo   []AttributeTypeAndValueMaybe `asn1:"explicit,optional,tag:8,omitempty"`
	// should be GeneralInfo []AttributeTypeAndValue, but EJBCA leaves out the NULL value of implicitConfirm
}

/*
Variant of pkix.AttributeTypeAndValue with optional Value,
used as workaround for EJBCA returning implicitConfirm without the NULL value:
*/
type AttributeTypeAndValueMaybe struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional,omitempty"`
	// Using the type 'any' here would be more correct, but it's not supported by the Go ASN.1 library.
}

// newPKIHeader(trans, sender, senderKID, implicitConfirm)
func newPKIHeader(transaction *Transaction, senderKID KeyIdentifier,
	implicitConfirm bool) (hdr PKIHeader) {
	hdr = PKIHeader{
		PVNO:          CMP2000,
		Sender:        MakeDirectoryName(transaction.senderDN),
		Recipient:     MakeDirectoryName(transaction.recipientDN),
		MessageTime:   time.Now().UTC(), // https://yossarian.net/til/post/go-s-encoding-asn1-can-produce-invalid-der-encodings/
		SenderKID:     senderKID,
		RecipientKID:  KeyIdentifier{},
		TransactionID: transaction.transactionID,
		SenderNonce:   transaction.senderNonce,
		RecipNonce:    transaction.recipNonce,
		// FreeText:    []UTF8String{},
		// GeneralInfo: []pkix.AttributeTypeAndValue{},
	}
	if implicitConfirm {
		hdr.GeneralInfo = []AttributeTypeAndValueMaybe{{Type: oidImplicitConfirm, Value: ASN1_NULL}}
	}
	return
}

func MakePKIHeader(trans *Transaction, implicitConfirm bool, secret string,
	certChain []*x509.Certificate) (
	hdr PKIHeader, err error) {

	macBased := secret != ""
	var senderKID KeyIdentifier
	if !macBased && len(certChain) > 0 {
		senderCert := certChain[0]
		trans.senderDN = senderCert.Subject.ToRDNSequence()
		if len(trans.recipientDN) == 0 {
			trans.recipientDN = senderCert.Issuer.ToRDNSequence()
		}
		senderKID = senderCert.SubjectKeyId
	} else {
		var senderName pkix.Name
		senderName.FillFromRDNSequence(&trans.senderDN)
		if senderName.CommonName == "" {
			err = fmt.Errorf("missing CommonName in sender DN to use as senderKID with MAC-based protection")
			return
		}
		senderKID = KeyIdentifier(senderName.CommonName)
	}
	if len(trans.senderDN) == 0 {
		err = fmt.Errorf("missing sender DN")
		return
	}
	if len(trans.recipientDN) == 0 {
		err = fmt.Errorf("missing recipient DN")
		return
	}
	if len(senderKID) == 0 {
		err = fmt.Errorf("empty senderKID")
		return
	}

	trans.senderNonce, err = CreateRandom(nonceLen)
	if err != nil { // should not happen
		err = fmt.Errorf("error creating senderNonce: %w", err)
		return
	}

	hdr = newPKIHeader(trans, senderKID, implicitConfirm)
	return
}

func (hdr *PKIHeader) HasImplicitConfirm() bool {
	for _, info := range hdr.GeneralInfo {
		if info.Type.Equal(oidImplicitConfirm) {
			return true
		}
	}
	return false
}
