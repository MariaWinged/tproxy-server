package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

var diagnosticIDs atomic.Uint64

// Only fixed event/reason strings and numeric metadata reach this logger.
// Never pass tokens, addresses, request objects, payloads or raw errors here.
func (s *Session) trace(event, fields string) {
	if s.debug {
		log.Printf("event=web_debug session=%d action=%s %s", s.debugID, event, fields)
	}
}

func (s *Session) traceStream(id uint32, event, reason string) {
	if s.debug {
		s.trace(event, fmt.Sprintf("stream=%d reason=%s", id, reason))
	}
}

func (s *Session) traceStreamTotals(id uint32, up, down uint64) {
	if s.debug {
		s.trace("stream_finished", fmt.Sprintf("stream=%d client_to_backend=%d backend_to_client=%d", id, up, down))
	}
}

func (s *backendStream) reason(reason string) {
	s.reasonOnce.Do(func() { s.session.traceStream(s.id, "stream_close", reason) })
}

func (s *Session) traceTransfer(direction string, lane uint32, cursor, next uint64, size int, err error) {
	if s.debug {
		s.trace(direction, fmt.Sprintf("lane=%d cursor=%d next=%d bytes=%d result=%s", lane, cursor, next, size, diagnosticError(err)))
	}
}

func (s *Session) traceFrame(direction string, t frame.Type, id uint32, payload []byte, ok bool) {
	if !s.debug {
		return
	}
	name := "OTHER"
	switch t {
	case frame.Open:
		name = "OPEN"
	case frame.Data:
		name = "DATA"
	case frame.Window:
		name = "WINDOW"
	case frame.Close:
		name = "CLOSE"
	}
	var credit uint32
	if t == frame.Window {
		credit, _ = frame.WindowAmount(payload)
	}
	s.trace("frame", fmt.Sprintf("direction=%s stream=%d type=%s bytes=%d credit=%d accepted=%t", direction, id, name, len(payload), credit, ok))
}

// Do not stringify err: network and HTTP errors can embed sensitive values.
func diagnosticError(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken_pipe"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrBackpressure):
		return "backpressure"
	case errors.Is(err, ErrConcurrent):
		return "concurrent"
	case errors.Is(err, ErrProtocol):
		return "protocol"
	case errors.Is(err, ErrClosed):
		return "session_closed"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	return "io_error"
}

// DiagnosticTransportError records a fixed operation name and a sanitized error class.
func (s *Session) DiagnosticTransportError(operation string, err error) {
	// Whitelist operations so a caller cannot accidentally log a request URL.
	if operation != "down_write" && operation != "up_read" && operation != "websocket_io" {
		operation = "transport"
	}
	s.trace(operation, "result="+diagnosticError(err))
}

// traceReadStateLocked requires session.mu and must not acquire connMu.
func (s *Session) traceReadStateLocked(id uint32, event, reason string, n, allowance int, accepted bool) {
	if !s.debug {
		return
	}
	state := s.streams[id]
	var credit uint64
	if state != nil {
		credit = state.sendCredit
	}
	costLimit, itemLimit := s.downlinkPendingLimits()
	s.trace(event, fmt.Sprintf("stream=%d reason=%s bytes=%d allowance=%d accepted=%t stream_present=%t session_closed=%t send_credit=%d pending_cost=%d pending_items=%d down_cost_limit=%d down_item_limit=%d", id, reason, n, allowance, accepted, state != nil, s.closed, credit, s.pendingCost, s.pendingItems, costLimit, itemLimit))
}

func (s *Session) traceReadState(id uint32, event, reason string, n, allowance int, accepted bool) {
	if !s.debug {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.traceReadStateLocked(id, event, reason, n, allowance, accepted)
}
