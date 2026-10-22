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
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/url"

	cmpissuerapi "github.com/siemens/cmpissuer/api/v1alpha1"
	"github.com/siemens/cmpissuer/internal/controllers"
)

func CMPHealthCheckerFromIssuerAndSecretData(issuerSpec *cmpissuerapi.IssuerSpec, SecretData map[string][]byte) (controllers.HealthChecker, error) {
	u, err := url.Parse(issuerSpec.CMPServerUrl)
	if err != nil {
		return nil, fmt.Errorf("error parsing CMP server URL: %w", err)
	}
	hostURL := u.Scheme + "://" + u.Host

	cmpHttpClient, err := MakeCmpHttpClient(hostURL, issuerSpec.TLSClientCert,
		issuerSpec.TLSClientKey, SecretData["TLSClientPassphrase"], string(SecretData["TLSTrusted"]))
	if err != nil {
		return nil, fmt.Errorf("error creating CMP HTTP(S) client: %w", err)
	}
	return &CmpHealthChecker{transport: cmpHttpClient}, nil
}

func CMPSignerFromIssuerAndSecretData(issuerSpec *cmpissuerapi.IssuerSpec, SecretData map[string][]byte) (controllers.Signer, error) {
	var err error
	cmpHttpClient, err := MakeCmpHttpClient(issuerSpec.CMPServerUrl, issuerSpec.TLSClientCert,
		issuerSpec.TLSClientKey, SecretData["TLSClientPassphrase"], string(SecretData["TLSTrusted"]))
	if err != nil {
		return nil, fmt.Errorf("error creating CMP HTTP(S) client: %w", err)
	}
	u, err := url.Parse(issuerSpec.CMPServerUrl)
	if err != nil {
		return nil, fmt.Errorf("error parsing CMP server URL: %w", err)
	}
	hostName := u.Hostname()
	recipient, err1 := String2Name("CN=" + hostName)
	if err1 != nil {
		return nil, err1
	}
	client := CMPClient{transport: cmpHttpClient, recipientDN: recipient.ToRDNSequence()}
	secret := string(SecretData["CmpSharedSecret"])
	if len(secret) == 0 {
		CMPSignerCert := issuerSpec.CMPSignerCert
		if len(CMPSignerCert) > 0 {
			cert, err := ParseCertificate([]byte(CMPSignerCert))
			if err != nil {
				return nil, fmt.Errorf("error parsing CMPSignerCert: %w", err)
			}
			client.certChain = []*x509.Certificate{cert}
		} else {
			return nil, errors.New("missing CMPSignerCert")
		}

		CMPSignerKey := issuerSpec.CMPSignerKey
		if len(CMPSignerKey) > 0 {
			_, client.privateKey, err = DecryptPrivKeyToPem(CMPSignerKey, SecretData["CMPSignerPassphrase"])
			if err != nil {
				log.Println("error decrypting CMPSignerKey:", err.Error())
				return nil, errors.New("error decrypting CMPSignerKey")
			}
		} else {
			return nil, errors.New("missing CMPSignerKey in secret")
		}
		log.Println("CMP client certificate and key successfully loaded")
		log.Printf("CMP client key: %T", client.privateKey)
	} else {
		client.sharedSecret = secret
	}

	CMPTrusted := issuerSpec.CMPTrusted
	if len(CMPTrusted) > 0 {
		Cert, err := ParseCertificate([]byte(CMPTrusted))
		if err != nil {
			log.Println("error parsing CMPTrusted:", err)
			return nil, fmt.Errorf("error parsing CMPTrusted: %w", err)
		}
		client.trustedCerts = []*x509.Certificate{Cert}
	}
	signer := CmpSigner{cmpClient: &client}
	return &signer, nil
}

func (checker *CmpHealthChecker) Check() error {
	return checker.transport.Check()
}

func (cmpSigner *CmpSigner) Sign(pkcs10Bytes []byte) (result []byte, err error) {

	pkcs10, err := ParsePKCS10CSR(pkcs10Bytes)
	if err != nil {
		return
	}
	if debug {
		log.Printf("%#v", pkcs10)
	}

	cmpClient := cmpSigner.cmpClient

	cmpClient.flags.acceptNewCertValidationFailure = true
	cmpClient.flags.preferCRMF = true

	trans, err := initTransaction(cmpClient)
	if err != nil {
		return
	}
	certificate, _, err1 := trans.RequestCertificate(pkcs10)
	if err1 != nil {
		err = fmt.Errorf("error requesting certificate: %w", err1)
		return
	}

	result = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
	return
}
