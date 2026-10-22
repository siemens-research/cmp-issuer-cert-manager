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
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func (client *CMPClient) sendReceivePKIMessage(requestMessage PKIMessage) (responseMessage PKIMessage, err error) {
	if debug {
		fmt.Println("Sending", requestMessage.BodyTypeName())
	}
	requestMessageAsDER, err1 := requestMessage.Marshal()
	if err1 != nil {
		err = err1
		return
	}

	cmplogConfig.mutex.Lock()
	defer cmplogConfig.mutex.Unlock()
	path := fmt.Sprintf("log/%s/", cmplogConfig.serverName)
	if dumpdebug {
		err = os.MkdirAll(path, 0755)
		if err != nil {
			return
		}
		cmplogConfig.dumpFileIndex = (cmplogConfig.dumpFileIndex + 1) % 10
		err := os.WriteFile(path+"req"+fmt.Sprint(cmplogConfig.dumpFileIndex)+".der", requestMessageAsDER, 0644)
		if err != nil {
			log.Printf("error writing request message to file: %v", err)
		}
	}
	if debug {
		fmt.Println("Sending : \n", base64.StdEncoding.EncodeToString(requestMessageAsDER))
	}
	responseMessageAsDER, err := client.transport.SendReceiveCMPMessage(requestMessageAsDER)
	if err != nil {
		return
	}
	if dumpdebug {
		err := os.WriteFile(path+"rsp"+fmt.Sprint(cmplogConfig.dumpFileIndex)+".der", responseMessageAsDER, 0644)
		if err != nil {
			log.Printf("error writing response message to file: %v", err)
		}
	}
	if debug {
		fmt.Println("Received : \n", base64.StdEncoding.EncodeToString(responseMessageAsDER))
	}

	responseMessage, err = ParsePKIMessage(responseMessageAsDER)
	if err == nil && debug {
		fmt.Println("Received", responseMessage.BodyTypeName(), "message")
	}
	return
}

func checkCertResponse(certRep *CertRep, desc string) (err error) {
	if certRep.Status.Status != Accepted {
		err = fmt.Errorf("certificate request not accepted according to %s:\n%s", desc, certRep.Status.String())
	}
	return
}

func (msg *PKIMessage) reportError(err error) error {
	desc := msg.BodyTypeName() + " message"
	errorContent := msg.Body.Error
	if errorContent != nil {
		if err != nil {
			warn.Printf("ignoring for CMP error message: %v\n", err)
		}

		errorCode := ""
		if errorContent.ErrorCode != 0 /* empty */ {
			errorCode = fmt.Sprintf(", code: %d", errorContent.ErrorCode)
		}
		errorDetails := ""
		if errorContent.ErrorDetails != nil {
			errorDetails, _ = ASN1String2String(errorContent.ErrorDetails) // rather suitable message also on error
			errorDetails = fmt.Sprintf(", details: '%s'", errorDetails)
		}
		err = fmt.Errorf("got CMP error message with %s%s%s",
			errorContent.PKIStatusInfo.String(), errorCode, errorDetails)
	} else if msg.Body.PkiConf != nil {
		if err != nil { // must be the case here for body.Tag != ErrorMessage
			warn.Printf("ignoring for CMP confirmation message: %v\n", err)
		}
		err = nil
	} else if msg.Body.CertRep != nil && msg.Body.CertRep.Status.Status != Accepted {
		if err != nil { // must be the case here for body.Tag != ErrorMessage
			warn.Printf("ignoring for %s: %v\n", desc, err)
		}
		err = checkCertResponse(msg.Body.CertRep, desc)

	}
	return err
}

func checkNonce(actual, reference []byte, msg string, isError bool, acceptNonMatchingNoncesInErrors bool) (err error) {
	if reference != nil && (actual == nil || !bytes.Equal(actual, reference)) {
		err = fmt.Errorf("%s: %v vs. %v", msg, actual, reference)
		if isError && acceptNonMatchingNoncesInErrors {
			warn.Println("ignoring for CMP error message:", err)
			err = nil
		}
	}
	return
}

/*
Send PKIMessage with given body to the CMP server and receive response of expectedType.
Request implicit confirmation in the request message header if implicitConfirm is true.
Use MAC-based protection and given sender in message header if global sharedSecret is not empty,
otherwise use signature-based protection with global privateKey and certChain.
Use global serverURL for HTTP(S).
Use global trustedCerts and untrustedCerts for checking signature-based protection.
Accept wrong or missing transactionID or recipNonce if global acceptNonMatchingNoncesInErrors is true.
Accept unprotected or wrongly protected pkiConf or negative responses if global acceptNonProtectedNegativeOrPKIConf is true.
*/
func (trans *Transaction) performRequest(body *PKIBody, implicitConfirm bool, expectedType int) (
	responseMessage PKIMessage, err error) {
	client := trans.cmpClient
	requestMessage, err := trans.MakePKIMessage(body, implicitConfirm, client.sharedSecret, client.privateKey, client.certChain)
	if err != nil {
		return
	}

	responseMessage, err = client.sendReceivePKIMessage(requestMessage)
	if err != nil {
		return
	}
	hdr := &responseMessage.Header

	isError := responseMessage.Body.Error != nil
	bodyType := responseMessage.BodyTypeName()
	err = checkEqualDirNames(
		hdr.Recipient, fmt.Sprintf("recipient of %v message", bodyType),
		ConvertFromASN1StringRDNSequence(trans.senderDN).String(), "our senderDN")
	if err != nil {
		warn.Println(err)
	}

	err = checkNonce(hdr.TransactionID, trans.transactionID,
		"likely due to invalid request message ASN.1 encoding, unexpected "+bodyType+" message transactionID", isError, client.flags.acceptNonMatchingNoncesInErrors)
	if err != nil {
		return
	}

	err = checkNonce(hdr.RecipNonce, trans.senderNonce, "unexpected "+bodyType+" message recipNonce", isError, client.flags.acceptNonMatchingNoncesInErrors)
	if err != nil {
		return
	}

	err = trans.cmpClient.checkProtection(&responseMessage, requestMessage.Header.ProtectionAlg, client.flags.acceptKeyUsageNoDigitalSignature)
	if err != nil && !client.flags.acceptNonProtectedNegativeOrPKIConf {
		return
	}
	if isError || err != nil {
		err = responseMessage.reportError(err)
		if err != nil {
			return
		}
	}

	if responseMessage.Body.Type != expectedType {
		err = fmt.Errorf("unexpected response message type: %v", bodyType)
		return
	}

	addCAcerts(responseMessage.ExtraCerts, true, &client.untrustedCerts, "untrusted certificates")
	trans.updateNonces(hdr)
	return
}
