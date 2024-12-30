package main

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

const testCredential = `{"id":"VqE96TwYOK9T4WrRUHbUM_05MNA","rawId":"VqE96TwYOK9T4WrRUHbUM_05MNA","type":"public-key","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViY1MnZAnMmJxqJzlH8rzKO1nPxe-M0af-Xnoq43VAeZk9dAAAAAPv8MAcVTk7MjAtuAgVX170AFFahPek8GDivU-Fq0VB21DP9OTDQpQECAyYgASFYIFVCUwPUU4IArNbXFRjveMFmTeE8Z-GedjyOTbNuCmY_IlggoyYLfHtCnMxb1eV22q7yAhpW6hHQ_e-hxvwmYFAIn-w","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWW14elpITnpZV1ptWkhOaGMyUm1ZWE5rWm1GelpHRnpaR0Z6WkdGelpHRnpaR0ZrWVdSaFpHRmtZV1JoWkdGa1lRIiwib3JpZ2luIjoiaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0"}}`

// const testCredential = `{"id":"04GKNyQJnWUh-NT0M5bLulayEmdFuzMngexK5KaT4Dk","rawId":"04GKNyQJnWUh-NT0M5bLulayEmdFuzMngexK5KaT4Dk","type":"public-key","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgB5KNTgEfk9HPwieLkEhTEFRqAKtbUVAw3qneUmmpNhECIGxXYpJE8uT2WbKWWMg42a0d4NeIJygbRebHOlwIoCp3Y3g1Y4FZAdcwggHTMIIBeqADAgECAgEBMAoGCCqGSM49BAMCMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwHhcNMTcwNzE0MDI0MDAwWhcNNDQxMTA4MjA1MjE5WjBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjWF-ZclQjmS8xWc6yCpnmdo8FEZoLCWMRj__31jf0vo-bDeLU9eVxKTf-0GZ7deGLyOrrwIDtLiRG6BWmZThAaMlMCMwDAYDVR0TAQH_BAIwADATBgsrBgEEAYLlHAIBAQQEAwIDCDAKBggqhkjOPQQDAgNHADBEAiBm2mLcZczBlI7H23Q46bZtNin_taCCXJdjrSk4jxY_fQIgB1-jiKC_LrZapBBjGzkTthGX5N2T7NW78NBZQdK1bMhoYXV0aERhdGFYpNTJ2QJzJicaic5R_K8yjtZz8XvjNGn_l56KuN1QHmZPQQAAAAEBAgMEBQYHCAECAwQFBgcIACDTgYo3JAmdZSH41PQzlsu6VrISZ0W7MyeB7ErkppPgOaUBAgMmIAEhWCAPwHVzMGEkMtwRI5oPebfwcc5QFVCKEIvqu7l8XsqIYiJYINjp9jmVXGnqAl--JXqgA-osRJlfSSCe84kMR-rzWrSM","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWW14elpITnpZV1ptWkhOaGMyUm1ZWE5rWm1GelpHRnpaR0Z6WkdGelpHRnpaR0ZrWVdSaFpHRmtZV1JoWkdGa1lRIiwib3JpZ2luIjoiaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0"}}`

func TestParsing(t *testing.T) {
	response := bytes.NewBufferString(testCredential)
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(response)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(parsedResponse.Response.CollectedClientData)
	cd, invalidErr := parsedResponse.Verify("YmxzZHNzYWZmZHNhc2RmYXNkZmFzZGFzZGFzZGFzZGFzZGFkYWRhZGFkYWRhZGFkYQ", false, "google.com", []string{"https://www.google.com"}, nil, protocol.TopOriginIgnoreVerificationMode, nil)
	if invalidErr != nil {
		t.Fatalf("%v", invalidErr.(*protocol.Error).DevInfo)
	}
	t.Logf("client data: %v", cd)
	pub := parsedResponse.Response.AttestationObject.AuthData.AttData.CredentialPublicKey
	t.Logf("keyStr: %s\n", webauthncose.DisplayPublicKey(pub))

	key, err := webauthncose.ParsePublicKey(pub)
	t.Logf("key: %+v\nerr: %v", key, err)
}

func TestParsePublickey(t *testing.T) {
	out, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(`webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFVCUwPUU4IArNbXFRjveMFmTeE8Z+GedjyOTbNuCmY/oyYLfHtCnMxb1eV22q7yAhpW6hHQ/e+hxvwmYFAIn+w= hullarb@MacBook-Pro.localdomain`))
	t.Logf("key: %v, comment: %v, opt: %v, rest: %v, err: %v\n", out, comment, options, rest, err)
}
