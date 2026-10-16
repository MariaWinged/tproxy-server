package session

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"
	"syscall"
	"testing"

	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

func TestDiagnosticsPrivacyAndDisabled(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	secret := "token-secret https://example.invalid/?secret=query payload-secret"
	s := &Session{debugID: 123}
	s.traceFrame("client_to_relay", frame.Data, 7, []byte(secret), true)
	s.DiagnosticTransportError(secret, errors.New(secret))
	if output.Len() != 0 {
		t.Fatal("diagnostics enabled by default")
	}
	s.debug = true
	s.traceFrame("client_to_relay", frame.Data, 7, []byte(secret), true)
	s.DiagnosticTransportError(secret, errors.New(secret))
	s.traceStreamTotals(7, 123, 456)
	s.DiagnosticTransportError("down_write", fmt.Errorf("%s: %w", secret, syscall.ECONNRESET))
	text := output.String()
	for _, sensitive := range []string{"token-secret", "https://", "secret=query", "payload-secret"} {
		if strings.Contains(text, sensitive) {
			t.Fatalf("sensitive data logged: %s", sensitive)
		}
	}
	for _, expected := range []string{"session=123", "type=DATA", "client_to_backend=123", "backend_to_client=456", "result=reset"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing metadata: %s", expected)
		}
	}
}
