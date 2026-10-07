// Package softauthn is a software WebAuthn authenticator for tests: it
// answers the options IDPico sends to navigator.credentials.create/get with
// the JSON a browser would post back. ES256 keys, "none" attestation, user
// presence and verification always asserted. Never use outside tests.
package softauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var b64 = base64.RawURLEncoding

// Authenticator holds the keys it created. Origin is what it reports as the
// calling page (set it to something else to simulate a phishing site).
type Authenticator struct {
	Origin string
	RPID   string
	creds  map[string]*credential
}

type credential struct {
	key        *ecdsa.PrivateKey
	userHandle []byte
	counter    uint32
}

// New returns an authenticator for pages at origin, relying party rpID.
func New(origin, rpID string) *Authenticator {
	return &Authenticator{Origin: origin, RPID: rpID, creds: map[string]*credential{}}
}

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

// Create answers navigator.credentials.create options with a new credential.
func (a *Authenticator) Create(optionsJSON []byte) (string, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	userHandle, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return "", fmt.Errorf("user.id: %w", err)
	}
	a.creds[b64.EncodeToString(id)] = &credential{key: key, userHandle: userHandle}

	x := key.PublicKey.X.FillBytes(make([]byte, 32))
	y := key.PublicKey.Y.FillBytes(make([]byte, 32))
	coseKey, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		return "", err
	}
	rpHash := sha256.Sum256([]byte(a.RPID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x45) // UP | UV | AT
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(authData, id...)
	authData = append(authData, coseKey...)
	attObj, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		return "", err
	}

	out, err := json.Marshal(map[string]any{
		"id": b64.EncodeToString(id), "rawId": b64.EncodeToString(id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal"},
		},
	})
	return string(out), err
}

// Get answers navigator.credentials.get options with an assertion from one
// of the allowed credentials this authenticator holds.
func (a *Authenticator) Get(optionsJSON []byte) (string, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return "", err
	}
	var id string
	var cred *credential
	for _, c := range o.PublicKey.AllowCredentials {
		if cr, ok := a.creds[c.ID]; ok {
			id, cred = c.ID, cr
			break
		}
	}
	if cred == nil {
		return "", errors.New("softauthn: no allowed credential held")
	}
	cred.counter++

	rpHash := sha256.Sum256([]byte(a.RPID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x05) // UP | UV
	authData = binary.BigEndian.AppendUint32(authData, cred.counter)
	clientData := a.clientData("webauthn.get", o.PublicKey.Challenge)
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.key, digest[:])
	if err != nil {
		return "", err
	}

	out, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(cred.userHandle),
		},
	})
	return string(out), err
}
