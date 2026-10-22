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
	"encoding/asn1"
	"fmt"
	"strings"
)

/*
	PKIStatus ::= INTEGER {
		accepted               (0),
		grantedWithMods        (1),
		rejection              (2),
		waiting                (3),
		revocationWarning      (4),
		revocationNotification (5),
		keyUpdateWarning       (6)
	}
*/
type PKIStatus int

const (
	Accepted PKIStatus = iota
	GrantedWithMods
	Rejection
	Waiting
	RevocationWarning
	RevocationNotification
	KeyUpdateWarning
)

func (status PKIStatus) String() string {
	switch status {
	case Accepted:
		return "accepted"
	case GrantedWithMods:
		return "grantedWithMods"
	case Rejection:
		return "rejection"
	case Waiting:
		return "waiting"
	case RevocationWarning:
		return "revocationWarning"
	case RevocationNotification:
		return "revocationNotification"
	case KeyUpdateWarning:
		return "keyUpdateWarning"
	default:
		return fmt.Sprintf("unknown PKIStatus %d", status)
	}
}

/*
	PKIFailureInfo ::= BIT STRING {
		badAlg              (0),
		badMessageCheck     (1),
		badRequest          (2),
		badTime             (3),
		badCertId           (4),
		badDataFormat       (5),
		wrongAuthority      (6),
		incorrectData       (7),
		missingTimeStamp    (8),
		badPOP              (9),
		certRevoked         (10),
		certConfirmed       (11),
		wrongIntegrity      (12),
		badRecipientNonce   (13),
		timeNotAvailable    (14),
		unacceptedPolicy    (15),
		unacceptedExtension (16),
		addInfoNotAvailable (17),
		badSenderNonce      (18),
		badCertTemplate     (19),
		signerNotTrusted    (20),
		transactionIdInUse  (21),
		unsupportedVersion  (22),
		notAuthorized       (23),
		systemUnavail       (24),
		systemFailure       (25),
		duplicateCertReq    (26)
*/
type PKIFailureInfo = asn1.BitString // asn1.Unmarshal would silently ignore PKIFailureInfo fields unless using this alias

func bitsToString(bits asn1.BitString) string {
	var result strings.Builder
	for i := 0; i < bits.BitLength; i++ {
		if bits.At(i) != 0 {
			result.WriteString("1")
		} else {
			result.WriteString("0")
		}
	}
	return result.String()
}

func FailureInfoString(failureInfo PKIFailureInfo) string {
	failureName := func(i int) string {
		switch i {
		case 0:
			return "badAlg"
		case 1:
			return "badMessageCheck"
		case 2:
			return "badRequest"
		case 3:
			return "badTime"
		case 4:
			return "badCertId"
		case 5:
			return "badDataFormat"
		case 6:
			return "wrongAuthority"
		case 7:
			return "incorrectData"
		case 8:
			return "missingTimeStamp"
		case 9:
			return "badPOP"
		case 10:
			return "certRevoked"
		case 11:
			return "certConfirmed"
		case 12:
			return "wrongIntegrity"
		case 13:
			return "badRecipientNonce"
		case 14:
			return "timeNotAvailable"
		case 15:
			return "unacceptedPolicy"
		case 16:
			return "unacceptedExtension"
		case 17:
			return "addInfoNotAvailable"
		case 18:
			return "badSenderNonce"
		case 19:
			return "badCertTemplate"
		case 20:
			return "signerNotTrusted"
		case 21:
			return "transactionIdInUse"
		case 22:
			return "unsupportedVersion"
		case 23:
			return "notAuthorized"
		case 24:
			return "systemUnavail"
		case 25:
			return "systemFailure"
		case 26:
			return "duplicateCertReq"
		default:
			return fmt.Sprintf("unknown failure %d", i)
		}
	}
	failStrings := []string{}
	for i := 0; i < failureInfo.BitLength; i++ {
		if failureInfo.At(i) != 0 {
			failStrings = append(failStrings, failureName(i))
		}
	}
	return strings.Join(failStrings, ", ")
}

/*
	PKIStatusInfo ::= SEQUENCE {
		status        PKIStatus,
		statusString  PKIFreeText     OPTIONAL,
		failInfo      PKIFailureInfo  OPTIONAL
	}
*/
type PKIStatusInfo struct {
	Status       PKIStatus
	StatusString PKIFreeText    `asn1:"optional,omitempty"`
	FailInfo     PKIFailureInfo `asn1:"optional,omitempty"`
}

func (status PKIStatusInfo) String() string {
	statusVal := fmt.Sprintf("%d = %s", status.Status, status.Status.String())
	statusString, _ := ASN1String2String(status.StatusString) // rather suitable message also on error
	failInfoVal := bitsToString(status.FailInfo)
	return fmt.Sprintf("status: %s, statusString: \"%v\", failInfo: '%s' = '%s'",
		statusVal, statusString, failInfoVal, FailureInfoString(status.FailInfo))
}
