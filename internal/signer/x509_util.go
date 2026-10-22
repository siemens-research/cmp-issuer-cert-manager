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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

// ReadCertificates loads PEM-encoded certificates from a file and returns a slice of x509.Certificate.
// This copes with extra data in between, such as private keys or comments in the PEM file.
func ReadCertificates(filename string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %v: %w", filename, err)
	}

	var certificates []*x509.Certificate
	var block *pem.Block
	for {
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate from file %v: %w", filename, err)
			}
			certificates = append(certificates, cert)
		}
	}

	return certificates, nil
}

func WriteCertificates(filename string, certificates []*x509.Certificate) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create certificate file %v: %w", filename, err)
	}
	defer file.Close()

	for _, cert := range certificates {
		err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return fmt.Errorf("failed to write certificate to file %v: %w", filename, err)
		}
	}

	return nil
}

func MakePKCS10CSR(subject pkix.Name, privKey crypto.PrivateKey, exts *[]pkix.Extension,
	attributes *[]pkix.AttributeTypeAndValueSET) (*x509.CertificateRequest, error) {
	// The x509 package has a weird interface for creating PKCS#10 CSRs

	csrTemplate := &x509.CertificateRequest{
		Subject: subject,
	}
	if exts != nil {
		csrTemplate.Extensions = *exts
	}
	if attributes != nil {
		csrTemplate.Attributes = *attributes
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(csrBytes)
}

func ParsePKCS10CSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block type must be CERTIFICATE")
	}
	return x509.ParseCertificate(block.Bytes)
}

/*
	AlgorithmIdentifier  ::=  SEQUENCE  {
		algorithm               OBJECT IDENTIFIER,
		parameters              ANY DEFINED BY algorithm OPTIONAL  }
			-- contains a value of the type
			-- registered for use with the
			-- algorithm object identifier value
*/

/*
	SubjectPublicKeyInfo  ::=  SEQUENCE  {
		algorithm            AlgorithmIdentifier,
		subjectPublicKey     BIT STRING  }
*/
type SubjectPublicKeyInfo struct { // same as x509.pkixPublicKey
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func MakeSubjectPublicKeyInfo(publicKey *crypto.PublicKey) SubjectPublicKeyInfo {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(*publicKey)
	if err != nil {
		log.Panicf("error marshaling PublicKey: %v", err)
	}
	var pubKey SubjectPublicKeyInfo
	_, err = asn1.Unmarshal(publicKeyBytes, &pubKey)
	if err != nil {
		log.Panicf("error unmarshaling PublicKey: %v", err)
	}
	return pubKey
}

/*
	BasicConstraints ::= SEQUENCE {
		cA                      BOOLEAN DEFAULT FALSE,
		pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
*/
type BasicConstraints struct {
	IsCA       bool `asn1:"optional,default:false"`
	MaxPathLen int  `asn1:"optional,default:-1,omitempty"`
}

func MakeBasicConstraints(critical bool, isCA bool, pathLen int) pkix.Extension {
	bc := BasicConstraints{
		IsCA:       isCA,
		MaxPathLen: pathLen,
	}
	bytes, _ := asn1.Marshal(bc)
	return pkix.Extension{
		Id:       oidExtensionBasicConstraints,
		Critical: critical,
		Value:    bytes,
	}
}

// more elegant and efficient than x509.marshalKeyUsage
// https://stackoverflow.com/questions/69412331/how-to-add-keyusage-to-certificate-signing-request-in-golang/79528659#79528659
func MakeKeyUsage(critical bool, ku x509.KeyUsage) pkix.Extension {
	if ku < 0 || ku >= (x509.KeyUsageDecipherOnly<<1) {
		log.Panicf("invalid key usage value: %d", ku)
	}

	var (
		bitBytes [2]byte
		nBits    int
		nBytes   int
		mask     byte
	)
	for nBits = 0; ku != 0; nBits++ {
		if mask == 0 {
			mask = 0x80
			nBytes++
		}
		if (ku & 1) != 0 {
			bitBytes[nBytes-1] |= mask
		}
		ku >>= 1
		mask >>= 1

	}

	bytes, _ := asn1.Marshal(asn1.BitString{Bytes: bitBytes[:nBytes], BitLength: nBits})
	return pkix.Extension{
		Id:       oidExtensionKeyUsage,
		Critical: critical,
		Value:    bytes,
	}
}

func KeyUsageString(keyUsage x509.KeyUsage) string {
	usage := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment (Non Repudiation)"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Signing"},
		{x509.KeyUsageCRLSign, "CRL Signing"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}

	usageStrings := []string{}
	for _, u := range usage {
		if keyUsage&u.bit != 0 {
			usageStrings = append(usageStrings, u.name)
		}
	}
	return strings.Join(usageStrings, ", ")
}

const anyEKU = x509.ExtKeyUsageAny

/*
	id-kp-cmcCA OBJECT IDENTIFIER ::= {
		iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) kp(3) 27 }

	 id-kp-cmcRA OBJECT IDENTIFIER ::= {
		iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) kp(3) 28 }

	 id-kp-cmKGA OBJECT IDENTIFIER ::= {
		iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) kp(3) 32 }
*/
const (
	ExtKeyUsageCMCCA = 27
	ExtKeyUsageCMCRA = 28
	ExtKeyUsageCMKGA = 32
)

func MakeExtendedKeyUsage(critical bool, usages []x509.ExtKeyUsage) pkix.Extension {
	oids := make([]asn1.ObjectIdentifier, len(usages))
	for i, usage := range usages {
		oids[i] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, int(usage)}
	}
	bytes, _ := asn1.Marshal(oids)
	return pkix.Extension{
		Id:       oidExtensionExtendedKeyUsage,
		Critical: critical,
		Value:    bytes,
	}
}

func ExtendedKeyUsageString(extKeyUsages []x509.ExtKeyUsage) string {

	usageNames := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "Server Authentication",
		x509.ExtKeyUsageClientAuth:                     "Client Authentication",
		x509.ExtKeyUsageCodeSigning:                    "Code Signing",
		x509.ExtKeyUsageEmailProtection:                "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSEC End System",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSEC Tunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSEC User",
		x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
		ExtKeyUsageCMCCA:                               "CMC CA",
		ExtKeyUsageCMCRA:                               "CMC RA",
		ExtKeyUsageCMKGA:                               "CM KGA",
	}

	usageStrings := []string{}
	for _, usage := range extKeyUsages {
		if name, ok := usageNames[usage]; ok {
			usageStrings = append(usageStrings, name)
		} else {
			usageStrings = append(usageStrings, fmt.Sprintf("Unknown (%d)", usage))
		}
	}
	return strings.Join(usageStrings, ", ")
}

type KeyIdentifier = []byte

var (
	oidExtensionSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionIssuerAltName          = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidExtensionBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionNameConstraints        = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionPolicyMappings         = asn1.ObjectIdentifier{2, 5, 29, 33}
	oidExtensionAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionPolicyConstraints      = asn1.ObjectIdentifier{2, 5, 29, 36}
	oidExtensionExtendedKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionAuthorityInfoAccess    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionInhibitAnyPolicy       = asn1.ObjectIdentifier{2, 5, 29, 54}
)

func MakeSubjectAlternativeName(critical bool, sans []GeneralName) pkix.Extension {
	bytes, _ := asn1.Marshal(sans)
	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: critical,
		Value:    bytes,
	}
}

func GeneralNamesString(gns []GeneralName) string {
	nameStrings := []string{}
	for _, gn := range gns {
		nameStrings = append(nameStrings, GeneralNameString(gn))
	}
	return strings.Join(nameStrings, ", ")
}

func Cert2Strings(cert *x509.Certificate) []string {
	lines := []string{}
	lines = append(lines, fmt.Sprint("Subject:", cert.Subject))
	lines = append(lines, fmt.Sprint("Issuer :", cert.Issuer))
	lines = append(lines, fmt.Sprint("NotBefore:", cert.NotBefore))
	lines = append(lines, fmt.Sprint("NotAfter :", cert.NotAfter))
	// lines = append(lines, fmt.Sprint("Certificate serial number", certificate.SerialNumber))
	// lines = append(lines, fmt.Sprint("Certificate signature algorithm", certificate.SignatureAlgorithm))
	lines = append(lines, fmt.Sprint("Key algorithm:", cert.PublicKeyAlgorithm))
	// lines = append(lines, fmt.Sprint("Certificate public key", certificate.PublicKey)

	var bcons, ku, eku string
	exts := []string{}
	for i, ext := range cert.Extensions {
		// fmt.Println("    Critical:", ext.Critical)
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			var altNames []GeneralName
			if _, err := asn1.Unmarshal(ext.Value, &altNames); err == nil {
				exts = append(exts, fmt.Sprint("Subject Alternative Names:", GeneralNamesString(altNames)))
			}
		} else if ext.Id.Equal(oidExtensionIssuerAltName) {
			var altNames []GeneralName
			if _, err := asn1.Unmarshal(ext.Value, &altNames); err == nil {
				exts = append(exts, fmt.Sprint("Issuer  Alternative Names:", GeneralNamesString(altNames)))
			}
		} else if ext.Id.Equal(oidExtensionBasicConstraints) {
			var bc BasicConstraints
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil {
				maxPath := ""
				if bc.MaxPathLen != -1 {
					maxPath = fmt.Sprintf("maxPathLen = %d", bc.MaxPathLen)
				}
				bcons = fmt.Sprint("Basic Constraints: isCA =", bc.IsCA, maxPath)

			}
		} else if ext.Id.Equal(oidExtensionKeyUsage) {
			ku = fmt.Sprint("Key Usage:", KeyUsageString(cert.KeyUsage))
		} else if ext.Id.Equal(oidExtensionExtendedKeyUsage) {
			eku = fmt.Sprint("Extended Key Usage:", ExtendedKeyUsageString(cert.ExtKeyUsage))
		} else if ext.Id.Equal(oidExtensionAuthorityKeyIdentifier) {
			var aki struct {
				KeyIdentifier             []byte          `asn1:"optional"`
				AuthorityCertIssuer       []asn1.RawValue `asn1:"optional"`
				AuthorityCertSerialNumber []byte          `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &aki); err == nil {
				// exts = append(exts, fmt.Sprint("Authority Key Identifier:", aki))
			}
		} else if ext.Id.Equal(oidExtensionSubjectKeyIdentifier) {
			var ski []byte
			if _, err := asn1.Unmarshal(ext.Value, &ski); err == nil {
				// exts = append(exts, fmt.Sprint("Subject Key Identifier:", ski))
			}
		} else if ext.Id.Equal(oidExtensionAuthorityInfoAccess) {
			var aia []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &aia); err == nil {
				// exts = append(exts, fmt.Sprint("Authority Information Access:", aia))
			}
		} else if ext.Id.Equal(oidExtensionCRLDistributionPoints) {
			var crlDistPoints []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &crlDistPoints); err == nil {
				// exts = append(exts, fmt.Sprint("CRL Distribution Points:", crlDistPoints))
			}
		} else if ext.Id.Equal(oidExtensionCertificatePolicies) {
			var certPolicies []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &certPolicies); err == nil {
				// exts = append(exts, fmt.Sprint("Certificate Policies:", certPolicies))
			}
		} else if ext.Id.Equal(oidExtensionPolicyMappings) {
			var policyMappings []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &policyMappings); err == nil {
				// exts = append(exts, fmt.Sprint("Policy Mappings:", policyMappings))
			} else {
				// exts = append(exts, fmt.Sprint("Policy Mappings:", err)
			}
		} else if ext.Id.Equal(oidExtensionNameConstraints) {
			var nameConstraints struct {
				Permitted []asn1.RawValue `asn1:"optional"`
				Excluded  []asn1.RawValue `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &nameConstraints); err == nil {
				// exts = append(exts, fmt.Sprint("Name Constraints:", nameConstraints))
			}
		} else if ext.Id.Equal(oidExtensionPolicyConstraints) {
			var policyConstraints struct {
				RequireExplicitPolicy *int `asn1:"optional"`
				InhibitPolicyMapping  *int `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &policyConstraints); err == nil {
				// exts = append(exts, fmt.Sprint("Policy Constraints:", policyConstraints))
			}
		} else if ext.Id.Equal(oidExtensionInhibitAnyPolicy) {
			var inhibitAnyPolicy *int
			if _, err := asn1.Unmarshal(ext.Value, &inhibitAnyPolicy); err == nil {
				// exts = append(exts, fmt.Sprint("Inhibit Any Policy:", inhibitAnyPolicy))
			}
		} else {
			exts = append(exts, fmt.Sprint("Extension", i+1, "OID:", ext.Id, "Value:", ext.Value))
		}
	}
	lines = append(lines, bcons, ku, eku)
	return append(lines, exts...)
}

func PrintCert(desc string, cert *x509.Certificate) {
	sep := "\n    "
	log.Printf("%s:%s%s\n", desc, sep, strings.Join(Cert2Strings(cert), sep))
}

func addCAcerts(certs []*x509.Certificate, noSelfIssued bool, list *[]*x509.Certificate, desc string) {
	for _, caCert := range certs {
		if !caCert.IsCA {
			warn.Printf("certificate with subject '%s' is not a CA certificate, not adding it to %s", caCert.Subject, desc)
		} else if noSelfIssued && caCert.Subject.String() == caCert.Issuer.String() {
			warn.Printf("certificate with subject '%s' is self-issued, not adding it to %s", caCert.Subject, desc)
		} else {
			// check if CA certificate is already in the list
			for _, cert := range *list {
				if cert.Equal(caCert) {
					return
				}
			}

			if debug {
				log.Printf("Adding CA certificate with subject '%s' to %s\n", caCert.Subject, desc)
			}
			*list = append(*list, caCert)

		}
	}
}

func ValidateCert(target *x509.Certificate, desc string, dnsName string, eku x509.ExtKeyUsage,
	trusted, untrusted, extra []*x509.Certificate) (chains [][]*x509.Certificate, err error) {

	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: x509.NewCertPool(),
		Roots:         x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{eku}, // otherwise, default is []ExtKeyUsage{ExtKeyUsageServerAuth}
	}
	for _, cert := range trusted {
		opts.Roots.AddCert(cert)
	}
	for _, cert := range extra { // add before untrusted, for maybe more efficient use
		opts.Intermediates.AddCert(cert)
	}
	for _, cert := range untrusted {
		opts.Intermediates.AddCert(cert)
	}
	chains, err = target.Verify(opts)
	chains, err = handleValidationResult(target, desc, opts, trusted, untrusted, extra, chains, err)
	return
}

// This function may be augmented or replaced by an application-specific callback function
func handleValidationResult(target *x509.Certificate, desc string, opts x509.VerifyOptions,
	trusted, untrusted, extra []*x509.Certificate, chains [][]*x509.Certificate,
	err error) ([][]*x509.Certificate, error) {
	if err != nil {
		PrintCert("Validation failed for "+desc+" certificate", target)
		if certErr, ok := err.(x509.CertificateInvalidError); ok {
			useWorkarounds := true
			if certErr.Cert != nil &&
				(!useWorkarounds || // workaround for possibly misleading certErr.Cert value from x509 package
					certErr.Reason != x509.IncompatibleUsage) {
				if certErr.Cert.Equal(target) {
					log.Printf("The target certificate ")
				} else {
					PrintCert("This certificate", certErr.Cert)
				}
			} else {
				log.Printf("Some certificate in the chain ")
			}
			if useWorkarounds && certErr.Reason == x509.IncompatibleUsage {
				// workaround for misleading and incomplete error message by certErr.Error() from x509 package
				ekus := opts.KeyUsages
				if len(ekus) == 0 {
					ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} // default used in the x509 package
				}
				err = fmt.Errorf("certificate is not authorized for required extended key usage(s): %v", ExtendedKeyUsageString(ekus))
			}
			fmt.Println("is invalid:", err.Error())
		} else if unknownAuthErr, ok := err.(x509.UnknownAuthorityError); ok {
			if unknownAuthErr.Cert != nil {
				if unknownAuthErr.Cert.Equal(target) {
					fmt.Println("For the target certificate ")
				} else {
					PrintCert("For this certificate", unknownAuthErr.Cert)
				}
			} else {
				fmt.Println("For some certificate in the chain ")
			}
			fmt.Println("cannot find suitable issuer certificate:", unknownAuthErr.Error())
			/*
				if unknownAuthErr.hintCert == nil {
					fmt.Println("Candidate certificate:")
					PrintCert(unknownAuthErr.hintCert)
				}
				if unknownAuthErr.hintErr != nil {
					fmt.Println("Error on candidate cerifiate:", unknownAuthErr.hintErr)
				}
			*/
			fmt.Println("Extra certificates:")
			for i, cert := range extra {
				PrintCert(fmt.Sprintf("Extra certificate %d", i+1), cert)
			}
			fmt.Println("Untrusted certificates:")
			for i, cert := range untrusted {
				PrintCert(fmt.Sprintf("Untrusted certificate %d", i+1), cert)
			}
			fmt.Println("Trusted certificates:")
			for i, cert := range trusted {
				PrintCert(fmt.Sprintf("Trust anchor certificate %d", i+1), cert)
			}
		} else { // includding x509.HostnameError and x509.SystemRootsError)
			fmt.Println("Available error details:", err.Error())
		}
		warn.Printf("Validation failed for %s certificate: %v", desc, err)
	}
	return chains, err
}
