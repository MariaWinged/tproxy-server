package session

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	s.traceReadState(7, "backend_read_end", "ok", 14, 64, true)
	if output.Len() != 0 {
		t.Fatal("diagnostics enabled by default")
	}
	s.debug = true
	s.traceFrame("client_to_relay", frame.Data, 7, []byte(secret), true)
	s.DiagnosticTransportError(secret, errors.New(secret))
	s.traceStreamTotals(7, 123, 456)
	s.traceReadState(7, "backend_read_end", diagnosticError(errors.New(secret)), 14, 64, true)
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

// A valid Read may return both data and EOF; those bytes must still be queued.
type diagnosticEOFConn struct{ net.Conn }

func (diagnosticEOFConn) Read(p []byte) (int, error) {
	return copy(p, []byte("payload-secret")), io.EOF
}

func TestBackendReaderDiagnosticsDataAndEOF(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	cfg := testConfig("127.0.0.1:1")
	s := newSession(sessionOptions{profile: &cfg.Profiles[0], limits: cfg.Limits, timeouts: cfg.Timeouts})
	s.debug = true
	backend := newBackendStream(s, 7, cfg.Profiles[0].Backend)
	defer backend.close()
	s.streams[7] = &streamState{backend: backend, sendCredit: frame.InitialStreamWindow}
	backend.readLoop(diagnosticEOFConn{})
	if backend.bytesDown.Load() != uint64(len("payload-secret")) {
		t.Fatal("backend read bytes were not counted")
	}
	if len(s.pendingFrames) != 1 || s.pendingFrames[0].typeCode != frame.Data {
		t.Fatal("data returned with EOF was not queued")
	}
	for _, expected := range []string{"action=backend_reader_start", "action=backend_read_begin", "action=backend_read_end stream=7 reason=eof bytes=14", "action=backend_data_queue stream=7 reason=queue_attempt bytes=14 allowance=0 accepted=true", "action=backend_reader_stop stream=7 reason=read_eof"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing diagnostic %s", expected)
		}
	}
	if strings.Contains(output.String(), "payload-secret") {
		t.Fatal("payload leaked")
	}
}

func TestBackendReadWaitDiagnosticsDistinguishBudgetAndCredit(t *testing.T) {
	for _, reason := range []string{"budget", "credit"} {
		t.Run(reason, func(t *testing.T) {
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(previous)
			cfg := testConfig("127.0.0.1:1")
			s := newSession(sessionOptions{profile: &cfg.Profiles[0], limits: cfg.Limits, timeouts: cfg.Timeouts})
			s.debug = true
			state := &streamState{sendCredit: frame.InitialStreamWindow, creditNotify: make(chan struct{}, 1)}
			s.streams[7] = state
			if reason == "credit" {
				state.sendCredit = 0
			} else {
				costLimit, _ := s.downlinkPendingLimits()
				s.pendingCost = costLimit
			}
			done := make(chan struct{})
			close(done)
			if _, ok := s.nextReadAllowance(7, done); ok {
				t.Fatal("blocked reader received allowance")
			}
			if !strings.Contains(output.String(), "action=backend_read_wait stream=7 reason="+reason) {
				t.Fatalf("missing wait classification: %s", output.String())
			}
		})
	}
}
