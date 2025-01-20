package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"syscall/js"

	"golang.org/x/crypto/ssh"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

var _ ssh.Signer = &webauthnSigner{}

type webauthnSigner struct {
	pk *webauthPublicKey
}

func (w *webauthnSigner) PublicKey() ssh.PublicKey {
	log.Print("publickey called")
	return w.pk
}

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
//
// The wire encoding for a webauthn-sk-ecdsa-sha2-nistp256@openssh.com
// signature is similar to the sk-ecdsa-sha2-nistp256@openssh.com format:

// 	string		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
// 	string		ecdsa_signature
// 	byte		flags
// 	uint32		counter
// 	string		origin
// 	string		clientData
// 	string		extensions

// Where "origin" is the HTTP origin making the signature, "clientData" is
// the JSON-like structure signed by the browser and "extensions" are any
// extensions used in making the signature.

func (w webauthnSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	log.Print("Sign called")

	challenge := base64.StdEncoding.EncodeToString(data)
	authPromise := js.Global().Call("retrievePublicKey", challenge)
	credentials, jserr := await(authPromise)
	if jserr != nil {
		return nil, fmt.Errorf("failed to retrieve public key: %v", jserr)
	}
	credsJSON := js.Global().Get("JSON").Call("stringify", credentials[0]).String()
	par, err := protocol.ParseCredentialRequestResponseBytes([]byte(credsJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %v", err)
	}
	type extra struct {
		Flags      byte
		Counter    uint32
		Origin     string
		ClientData string
		Extensions string
	}
	sigExtra := extra{
		Flags:      byte(par.Response.AuthenticatorData.Flags),
		Counter:    par.Response.AuthenticatorData.Counter,
		Origin:     par.Response.CollectedClientData.Origin,
		ClientData: string(par.Raw.AssertionResponse.ClientDataJSON),
	}
	type ECDSASignature struct {
		R, S *big.Int
	}
	e := &ECDSASignature{}
	_, err = asn1.Unmarshal(par.Response.Signature, e)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %v", err)
	}
	sig := ssh.Marshal(e)
	return &ssh.Signature{
		Format: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		Blob:   sig,
		Rest:   ssh.Marshal(sigExtra),
	}, nil
}

func sshPublicKey(X, Y, hostName string) *webauthPublicKey {
	x, _ := big.NewInt(0).SetString(X, 10)
	y, _ := big.NewInt(0).SetString(Y, 10)
	return &webauthPublicKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
			// X:     big.NewInt(0).SetBytes(pkd.XCoord),
			// Y:     big.NewInt(0).SetBytes(pkd.YCoord),
		},
		application: hostName,
	}
}

func await(awaitable js.Value) ([]js.Value, []js.Value) {
	then := make(chan []js.Value)
	defer close(then)
	thenFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		then <- args
		return nil
	})
	defer thenFunc.Release()

	catch := make(chan []js.Value)
	defer close(catch)
	catchFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		catch <- args
		return nil
	})
	defer catchFunc.Release()

	awaitable.Call("then", thenFunc).Call("catch", catchFunc)

	select {
	case result := <-then:
		return result, nil
	case err := <-catch:
		return nil, err
	}
}

// based on skECDSAPublicKey in x/crypto/ssh/keys.go
type webauthPublicKey struct {
	application string
	ecdsa.PublicKey
}

func (k webauthPublicKey) Type() string {
	return "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
}

func (k webauthPublicKey) Marshal() []byte {
	keyBytes := elliptic.Marshal(k.Curve, k.X, k.Y)
	w := struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}{
		k.Type(),
		"nistp256",
		keyBytes,
		k.application,
	}

	return ssh.Marshal(&w)
}

func (w webauthPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return nil
}

var parsePublicKey = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
	credsJSON := args[0].String()
	log.Printf("keyjson: %s", credsJSON)
	par, err := protocol.ParseCredentialRequestResponseBytes([]byte(credsJSON))
	if err != nil {
		panic(fmt.Sprintf("failed to parse credential: %v", err))
	}
	log.Printf("par: %v", par)
	pub := par.Response.AuthenticatorData.AttData.CredentialPublicKey
	log.Printf("pub: %v", pub)
	key, err := webauthncose.ParsePublicKey(pub)
	if err != nil {
		panic(fmt.Sprintf("failed to parse public key: %v", err))
	}
	hostname := js.Global().Get("window").Get("location").Get("hostname").String()
	pkd := key.(webauthncose.EC2PublicKeyData)
	pk := sshPublicKey(big.NewInt(0).SetBytes(pkd.XCoord).String(), big.NewInt(0).SetBytes(pkd.YCoord).String(), hostname)
	return js.ValueOf(map[string]interface{}{
		"sshKey":   string(ssh.MarshalAuthorizedKey(pk)),
		"hostName": hostname,
		"x":        big.NewInt(0).SetBytes(pkd.XCoord).String(),
		"y":        big.NewInt(0).SetBytes(pkd.YCoord).String(),
		"ID":       base64.StdEncoding.EncodeToString(par.RawID),
	})
})
