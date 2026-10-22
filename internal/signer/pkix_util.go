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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"strings"
)

func MakeChoice(tag int, IsCompound bool, bytes []byte) asn1.RawValue {
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: IsCompound,
		Bytes:      bytes,
	}
}

func GetChoiceBytes(raw asn1.RawValue, tag int, choice, desc string) ([]byte, error) {
	if raw.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("unexpected class %d for %s choice of %s", raw.Class, choice, desc)
	}
	if raw.Tag != tag {
		return nil, fmt.Errorf("unexpected tag %d for %s choice of %s", raw.Tag, choice, desc)
	}
	if raw.Bytes == nil {
		return nil, fmt.Errorf("unexpected nil bytes for %s choice of %s", choice, desc)
	}
	return raw.Bytes, nil
}

type ASN1_Null = asn1.RawValue

/*
Null ::= NULL
*/
var ASN1_NULL = ASN1_Null{
	// Class: asn1.ClassUniversal
	Tag: asn1.TagNull,
	// IsCompound: false
	// Bytes: nil
} // DER encoding of NULL is 05 00

func stripSequence(encodedSequence []byte) []byte {
	var raw asn1.RawValue
	_, err := asn1.Unmarshal(encodedSequence, &raw)
	if err != nil {
		log.Panicf("error unmarshaling ASN.1 data: %v", err)
	}
	if raw.Tag != asn1.TagSequence {
		log.Panicf("missing SEQUENCE tag")
	}
	return raw.Bytes
}

func ChoiceConvertEx(tag int, source any, stripSEQUENCE bool) (result asn1.RawValue) {
	bytes, err := asn1.Marshal(source)
	if err != nil {
		log.Panicf("failed to marshal %v with tag %d: %v", source, tag, err)
	}
	if stripSEQUENCE {
		bytes = stripSequence(bytes)
	}
	return MakeChoice(tag, true, bytes)
}

func ChoiceConvert(tag int, source any) (result asn1.RawValue) {
	return ChoiceConvertEx(tag, source, false)
}

type IA5String string

/*
	GeneralName ::= CHOICE {
		otherName                       [0]     AnotherName,
		rfc822Name                      [1]     IA5String,
		dNSName                         [2]     IA5String,
		x400Address                     [3]     ORAddress,
		directoryName                   [4]     Name,
		ediPartyName                    [5]     EDIPartyName,
		uniformResourceIdentifier       [6]     IA5String,
		iPAddress                       [7]     OCTET STRING,
		registeredID                    [8]     OBJECT IDENTIFIER }
*/
type GeneralName = asn1.RawValue

const (
	otherName = iota
	rfc822Name
	dNSName
	x400Address
	directoryName
	ediPartyName
	uniformResourceIdentifier
	iPAddress
	registeredID
)

/*
	OtherName ::= SEQUENCE {
		type-id    OBJECT IDENTIFIER,
		value      [0] EXPLICIT ANY DEFINED BY type-id }
*/
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"explicit,tag:0"`
}

/*
Name ::= CHOICE { -- only one possibility for now --

	rdnSequence  RDNSequence }
*/
type Name struct {
	RDNSequence pkix.RDNSequence
}

func (name Name) String() (result string) {
	return pkix.RDNSequence(name.RDNSequence).String()
}

func MakeEmailAddress(name string) GeneralName {
	return MakeChoice(rfc822Name, false, []byte(name))
}

func MakeDNSName(name string) GeneralName {
	return MakeChoice(dNSName, false, []byte(name))
}

func MakeDirectoryName(dirName pkix.RDNSequence) GeneralName {
	return ChoiceConvert(directoryName, dirName)
}

func MakeURL(url string) GeneralName {
	return MakeChoice(uniformResourceIdentifier, false, []byte(url))
}

func MakeIPAddress(ip []byte) GeneralName {
	return MakeChoice(iPAddress, false, ip)
}

func GeneralNameString(gn GeneralName) string {
	switch gn.Tag {
	case otherName:
		var on OtherName
		_, err := asn1.Unmarshal(gn.Bytes, &on)
		if err != nil {
			panic(err)
		}
		return fmt.Sprintf("otherName with OID %s and value: %v", on.TypeID.String(), on.Value.Bytes)
	case rfc822Name:
		return "email address: " + string(gn.Bytes)
	case dNSName:
		return "DNSName: " + string(gn.Bytes)
	case directoryName:
		name, err := extractDirectoryName(gn)
		if err != nil {
			panic(err)
		}
		return "DirectoryName: " + name.String()
	case uniformResourceIdentifier:
		return "URL: " + string(gn.Bytes)
	case iPAddress:
		return fmt.Sprintf("IP address: %v", gn.Bytes)
	default:
		return fmt.Sprintf("GeneralName of type %d with value: %v", gn.Tag, gn.Bytes)
	}
}

func extractDirectoryName(gn GeneralName) (pkix.Name, error) {
	n := pkix.Name{}
	var name pkix.RDNSequence
	choiceBytes, err := GetChoiceBytes(gn, directoryName, "directoryName", "GeneralName")
	if err != nil {
		return n, err
	}
	_, err = asn1.Unmarshal(choiceBytes, &name)
	if err != nil {
		return n, fmt.Errorf("failed to parse directoryName: %w", err)
	}
	n.FillFromRDNSequence(&name)
	return n, nil
}

func checkEqualDirNames(generalName GeneralName, desc string, dirName string, desc2 string) (err error) {
	if generalName.Tag != directoryName {
		return fmt.Errorf("unexpected GeneralName type %d of %s", generalName.Tag, desc)
	}
	name, err := extractDirectoryName(generalName)
	if err != nil {
		return fmt.Errorf("failed to obtain directoryName of %s: %w", desc, err)
	}
	if name.String() != dirName {
		return fmt.Errorf("%s: '%s' does not match %s: '%s'",
			desc, name.String(), desc2, dirName)
	}
	return nil
}

func String2Name(dn string) (pkix.Name, error) {
	var name pkix.Name
	if dn == "" || dn == "/" {
		return name, nil // NullDN
	}
	var parts []string
	if dn[0] == '/' {
		parts = strings.Split(dn[1:], "/")
	} else {
		parts = strings.Split(dn, ",")
	}
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return name, fmt.Errorf("invalid DN format in '%s'", dn)
		}
		key, value := kv[0], kv[1]
		switch key {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = append(name.Organization, value)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, value)
		case "L":
			name.Locality = append(name.Locality, value)
		case "ST":
			name.Province = append(name.Province, value)
		case "C":
			name.Country = append(name.Country, value)
		case "Street":
			name.StreetAddress = append(name.StreetAddress, value)
		case "PostalCode":
			name.PostalCode = append(name.PostalCode, value)
		default:
			return name, fmt.Errorf("unsupported DN element key: %s", key)
		}
	}
	return name, nil
}

type UTF8String = asn1.RawValue

func ASN1String2String(text []UTF8String) (result string, err error) {
	for _, rawValue := range text {
		var str string
		if rawValue.Bytes != nil {
			str = string(rawValue.Bytes)
		} else {
			str = fmt.Sprintf("(failed to parse ASN.1 string ending '%v')", rawValue)
			err = errors.New(str)
		}
		if result != "" {
			result += "\n"
		}
		result += str
	}
	return
}

func String2UTF8String(text string) UTF8String {
	return UTF8String{
		Tag:   asn1.TagUTF8String,
		Class: asn1.ClassUniversal,
		Bytes: []byte(text),
	}
}

/*
	AttributeTypeAndValue ::= SEQUENCE {
		type     AttributeType,
		value    AttributeValue }

	AttributeType ::= OBJECT IDENTIFIER

	AttributeValue ::= ANY -- DEFINED BY AttributeType
*/
// see type pkix.AttributeTypeAndValue

func ConvertFromASN1StringRDNSequence(rdnSeq pkix.RDNSequence) pkix.RDNSequence {
	var stringRDNSequence pkix.RDNSequence
	for _, rdnSet := range rdnSeq {
		var stringRDNSet pkix.RelativeDistinguishedNameSET
		for _, atv := range rdnSet {
			var str string
			if s, ok := atv.Value.(string); ok {
				str = s
			} else {
				str = string(atv.Value.(asn1.RawValue).Bytes)
			}
			stringATV := pkix.AttributeTypeAndValue{
				Type:  atv.Type,
				Value: str,
			}
			stringRDNSet = append(stringRDNSet, stringATV)
		}
		stringRDNSequence = append(stringRDNSequence, stringRDNSet)
	}

	return stringRDNSequence
}

// workaround for asn1.Marshal accepting asn1 tag "utf8" only for string values
func ConvertToUTF8StringRDNSequence(rdnSeq pkix.RDNSequence) pkix.RDNSequence {
	var utf8RDNSequence pkix.RDNSequence
	for _, rdnSet := range rdnSeq {
		var utf8RDNSet pkix.RelativeDistinguishedNameSET
		for _, atv := range rdnSet {
			utf8ATV := pkix.AttributeTypeAndValue{
				Type:  atv.Type,
				Value: String2UTF8String(fmt.Sprintf("%v", atv.Value)),
			}
			utf8RDNSet = append(utf8RDNSet, utf8ATV)
		}
		utf8RDNSequence = append(utf8RDNSequence, utf8RDNSet)
	}

	return utf8RDNSequence
}
