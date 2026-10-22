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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"log"
	"strings"

	ypkcs8 "github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
)

func DecryptPrivKeyToPem(pemEncryptedKey string, passphrase []byte) ([]byte, crypto.PrivateKey, error) {
	if !strings.Contains(pemEncryptedKey, "ENCRYPTED") {
		// assume unencrypred key
		privateKey, err := ParsePrivateKey([]byte(pemEncryptedKey))
		return []byte(pemEncryptedKey), privateKey, err
	}

	if len(passphrase) == 0 {
		return nil, nil, errors.New("private key is encrypted but no passphrase given")
	}
	// try ssh decryption first, then PKCS8
	var decryptedKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(pemEncryptedKey), passphrase)
	if err != nil {
		block, _ := pem.Decode([]byte(pemEncryptedKey))
		if block == nil {
			return nil, nil, errors.New("failed to decode PEM encoded key")
		}

		// 3. Decrypt the key using the password
		decryptedKey, err = ypkcs8.ParsePKCS8PrivateKey(block.Bytes, passphrase)
		if err != nil {
			return nil, nil, err
		}
	}
	marshalPrivKey, err := x509.MarshalPKCS8PrivateKey(decryptedKey)
	if err != nil {
		return nil, nil, err
	}
	var priv_blk = pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshalPrivKey,
	}
	ret := pem.EncodeToMemory(&priv_blk)
	return ret, decryptedKey, nil
}

var randomSalt, _ = CreateRandom(16) // for MAC-based protection

func init() {
	var err error
	randomSalt, err = CreateRandom(16) // for MAC-based protection
	if err != nil {
		panic(err.Error())
	}
}

func CreateRandom(n int) (randomBytes []byte, err error) {
	randomBytes = make([]byte, n)
	nRead, err := rand.Read(randomBytes)

	if err != nil {
		return nil, fmt.Errorf("RND read err: %v", err)
	}
	if nRead != n {
		return nil, fmt.Errorf("RND read returned unexpected number of bytes; %d != %d", nRead, n)
	}
	return
}

func Hash(data []byte, hashAlg crypto.Hash) []byte {
	h := hashAlg.New()
	_, err := h.Write(data)
	if err != nil {
		log.Panicf("error writing data of length %d to hash: %v", len(data), err)
	}
	return h.Sum(nil)
}

var hmacAlgorithmDetails = []struct {
	mac_oid  asn1.ObjectIdentifier
	name     string
	hash_oid asn1.ObjectIdentifier
	hash     func() hash.Hash
}{
	{oidHMACWithSHA1, "HMAC-SHA1", oidSHA1, sha1.New},
	{oidHMACWithSHA256, "HMAC-SHA256", oidSHA256, sha256.New},
	{oidHMACWithSHA384, "HMAC-SHA384", oidSHA384, sha512.New384},
	{oidHMACWithSHA512, "HMAC-SHA512", oidSHA512, sha512.New},
}

func hmac2hashOID(oid asn1.ObjectIdentifier) (hashAlg asn1.ObjectIdentifier, err error) {
	for _, mac := range hmacAlgorithmDetails {
		if mac.mac_oid.Equal(oid) {
			return mac.hash_oid, nil
		}
	}
	return nil, fmt.Errorf("unknown MAC algorithm OID: %s", oid)
}

func hmacOID2HashFunc(oid asn1.ObjectIdentifier) (hash func() hash.Hash, err error) {
	for _, mac := range hmacAlgorithmDetails {
		if mac.mac_oid.Equal(oid) {
			return mac.hash, nil
		}
	}
	return nil, fmt.Errorf("unknown MAC algorithm OID: %s", oid)
}

func hashOID2Hash(oid asn1.ObjectIdentifier) (hash hash.Hash, err error) {
	for _, mac := range hmacAlgorithmDetails {
		if mac.hash_oid.Equal(oid) {
			return mac.hash(), nil
		}
	}
	return nil, fmt.Errorf("unknown hash algorithm OID: %s", oid)
}

// https://www.rfc-editor.org/rfc/rfc4211.html#section-4.4
/*
	PBMParameter ::= SEQUENCE {
		salt                OCTET STRING,
		-- note:  implementations MAY wish to limit acceptable sizes
		-- of this string to values appropriate for their environment
		-- in order to reduce the risk of denial-of-service attacks
		owf                 AlgorithmIdentifier,
		-- AlgId for a One-Way Function (SHA-1 recommended)
		iterationCount      INTEGER,
		-- number of times the OWF is applied
		-- note:  implementations MAY wish to limit acceptable sizes
		-- of this integer to values appropriate for their environment
		-- in order to reduce the risk of denial-of-service attacks
		mac                 AlgorithmIdentifier
		-- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
	}   -- or HMAC [RFC2104, RFC2202])
*/
type PBMParameter struct {
	Salt           []byte
	OWF            pkix.AlgorithmIdentifier
	IterationCount int
	MAC            pkix.AlgorithmIdentifier
}

func getMACAlgorithmIdentifier(mac_oid, hmac_oid asn1.ObjectIdentifier) (protAlg pkix.AlgorithmIdentifier, err error) {
	if !mac_oid.Equal(oidPBM) { // TODO: support also PBMAC1
		err = errors.New("so far, only PBM is supported as MAC-based algorithm")
		return
	}

	hash_oid, err1 := hmac2hashOID(hmac_oid)
	if err1 != nil {
		err = err1
		return
	}
	pbmParametersAsDER, err := asn1.Marshal(PBMParameter{
		Salt: randomSalt,
		OWF: pkix.AlgorithmIdentifier{
			Algorithm: hash_oid,
			// Parameters: []byte{},
		},
		IterationCount: 10000,
		MAC: pkix.AlgorithmIdentifier{
			Algorithm: hmac_oid,
			// Parameters: []byte{},
		},
	}) // TODO: maybe make parameters configurable
	if err != nil {
		err = fmt.Errorf("error marshalling PBM parameters: %w", err)
		return
	}

	var pbmParameters asn1.RawValue
	pbmParameters.FullBytes = pbmParametersAsDER
	protAlg = pkix.AlgorithmIdentifier{
		Algorithm:  oidPBM,
		Parameters: pbmParameters,
	}
	return
}

var (
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidPBM = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
)

/*
The PBM algorithm is a password-based MAC algorithm.  It is
described in RFC 4210, section 4.4.  The algorithm is a
password-based key derivation function that uses a one-way
function (OWF) and a MAC algorithm.
In the protectionAlg, the salt value is appended to the shared
secret input.  The OWF is then applied iterationCount times, where
the salted secret is the input to the first iteration and, for each
successive iteration, the input is set to be the output of the
previous iteration.  The output of the final iteration (called
"BASEKEY" for ease of reference, with a size of "H") is what is used
to form the symmetric key.
*/
func derivePBMBaseKey(secret string, salt []byte, owf hash.Hash, iterations int) (baseKey []byte) {
	// Initial hash is the password + salt
	calculatingBaseKey := append([]byte(secret), salt...)

	for range iterations {
		owf.Reset()
		owf.Write(calculatingBaseKey)
		calculatingBaseKey = owf.Sum(nil)
	}

	baseKey = calculatingBaseKey

	return
}

func HMAC(data []byte, alg pkix.AlgorithmIdentifier, secret string) (result []byte, err error) {

	if !alg.Algorithm.Equal(oidPBM) { // TODO: support also PBMAC1
		err = errors.New("so far, only PBM is supported as MAC-based algorithm")
		return
	}

	var pbmParameters PBMParameter
	_, err = asn1.Unmarshal(alg.Parameters.FullBytes, &pbmParameters)
	if err != nil {
		err = fmt.Errorf("error unmarshaling pbmParameters: %w", err)
		return
	}

	oneWayFunction, err1 := hashOID2Hash(pbmParameters.OWF.Algorithm)
	if err1 != nil {
		err = fmt.Errorf("error getting OWF hash algorithm for HMAC: %w", err1)
		return
	}

	baseKey := derivePBMBaseKey(secret, pbmParameters.Salt, oneWayFunction, pbmParameters.IterationCount)

	hashFunction, err1 := hmacOID2HashFunc(pbmParameters.MAC.Algorithm)
	if err1 != nil {
		err = fmt.Errorf("error getting hash algorithm for HMAC: %w", err1)
		return
	}
	hmacFunction := hmac.New(hashFunction, baseKey)

	hmacFunction.Write(data)
	return hmacFunction.Sum(nil), nil

}

func isKnownMACbased(alg asn1.ObjectIdentifier) bool {
	return alg.Equal(oidPBM) // TODO: support also PBMAC1
}

func protAlgString(protAlg pkix.AlgorithmIdentifier) string {
	if protAlg.Algorithm == nil {
		return "none"
	}
	if isKnownMACbased(protAlg.Algorithm) {
		return "MAC-based"
	}
	return "signature-based"
}
