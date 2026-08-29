package middleend

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestSignalSubmissionReadyCoalescesWithoutLosingLaterSignal(t *testing.T) {
	ready := make(chan struct{}, 1)
	var waitGroup sync.WaitGroup
	for range 128 {
		waitGroup.Go(func() {
			for range 128 {
				signalSubmissionReady(ready)
			}
		})
	}
	waitGroup.Wait()
	if got := len(ready); got != 1 {
		t.Fatalf("coalesced signal count = %d, want 1", got)
	}
	<-ready

	signalSubmissionReady(ready)
	select {
	case <-ready:
	default:
		t.Fatal("later capacity release signal was lost")
	}
}

func TestLinkLimitsValidate(t *testing.T) {
	valid := LinkLimits{
		MaxPendingSubmissions:     8,
		MaxPendingSubmissionBytes: MaxMEFrameSize,
		MaxPendingEvents:          8,
		MaxPendingEventBytes:      MaxMEFrameSize,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*LinkLimits)
	}{
		{name: "submission items", mutate: func(limits *LinkLimits) { limits.MaxPendingSubmissions = 0 }},
		{name: "submission bytes", mutate: func(limits *LinkLimits) { limits.MaxPendingSubmissionBytes = 0 }},
		{name: "event items", mutate: func(limits *LinkLimits) { limits.MaxPendingEvents = 0 }},
		{name: "event bytes", mutate: func(limits *LinkLimits) { limits.MaxPendingEventBytes = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := valid
			test.mutate(&limits)
			if err := limits.Validate(); !errors.Is(err, ErrInvalidLinkLimits) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}
}

func TestLinkLimitsValidateSafetyCeilings(t *testing.T) {
	if MaxLinkQueueItems != 4096 || MaxLinkQueueBytes != 512*1024*1024 {
		t.Fatalf("local queue ceilings = %d items and %d bytes", MaxLinkQueueItems, MaxLinkQueueBytes)
	}
	maximum := LinkLimits{
		MaxPendingSubmissions:     MaxLinkQueueItems,
		MaxPendingSubmissionBytes: MaxLinkQueueBytes,
		MaxPendingEvents:          MaxLinkQueueItems,
		MaxPendingEventBytes:      MaxLinkQueueBytes,
	}
	if err := maximum.Validate(); err != nil {
		t.Fatalf("Validate exact ceilings: %v", err)
	}

	maximumInt := int(^uint(0) >> 1)
	dimensions := []struct {
		name    string
		ceiling int
		set     func(*LinkLimits, int)
	}{
		{
			name:    "submission items",
			ceiling: MaxLinkQueueItems,
			set:     func(limits *LinkLimits, value int) { limits.MaxPendingSubmissions = value },
		},
		{
			name:    "submission bytes",
			ceiling: MaxLinkQueueBytes,
			set:     func(limits *LinkLimits, value int) { limits.MaxPendingSubmissionBytes = value },
		},
		{
			name:    "event items",
			ceiling: MaxLinkQueueItems,
			set:     func(limits *LinkLimits, value int) { limits.MaxPendingEvents = value },
		},
		{
			name:    "event bytes",
			ceiling: MaxLinkQueueBytes,
			set:     func(limits *LinkLimits, value int) { limits.MaxPendingEventBytes = value },
		},
	}
	values := []struct {
		name        string
		value       func(int) int
		wantInvalid bool
	}{
		{name: "exact ceiling", value: func(ceiling int) int { return ceiling }},
		{name: "ceiling plus one", value: func(ceiling int) int { return ceiling + 1 }, wantInvalid: true},
		{name: "maximum int minus one", value: func(int) int { return maximumInt - 1 }, wantInvalid: true},
		{name: "maximum int", value: func(int) int { return maximumInt }, wantInvalid: true},
	}
	for _, dimension := range dimensions {
		t.Run(dimension.name, func(t *testing.T) {
			for _, value := range values {
				t.Run(value.name, func(t *testing.T) {
					limits := LinkLimits{
						MaxPendingSubmissions:     1,
						MaxPendingSubmissionBytes: 1,
						MaxPendingEvents:          1,
						MaxPendingEventBytes:      1,
					}
					dimension.set(&limits, value.value(dimension.ceiling))
					err := limits.Validate()
					if value.wantInvalid && !errors.Is(err, ErrInvalidLinkLimits) {
						t.Fatalf("Validate error = %v, want %v", err, ErrInvalidLinkLimits)
					}
					if !value.wantInvalid && err != nil {
						t.Fatalf("Validate: %v", err)
					}
				})
			}
		})
	}
}

func TestLinkSubmissionValidate(t *testing.T) {
	requestPayload, err := (ProxyRequest{
		Flags:        ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2 | ProxyRequestFlagIntermediate,
		ConnectionID: 41,
		RemoteAddr:   netip.MustParseAddrPort("192.0.2.1:1234"),
		ProxyAddr:    netip.MustParseAddrPort("198.51.100.2:443"),
		Packet:       validEncryptedPacket(EncryptedMessageHeaderSize),
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	tests := []struct {
		name       string
		submission LinkSubmission
		want       error
	}{
		{
			name:       "proxy request",
			submission: LinkSubmission{SubmissionID: 1, ConnectionID: 41, Payload: requestPayload},
		},
		{
			name:       "close connection",
			submission: LinkSubmission{SubmissionID: 2, ConnectionID: 41, Payload: (CloseConnection{ConnectionID: 41}).MarshalBinary()},
		},
		{
			name:       "ping",
			submission: LinkSubmission{SubmissionID: 3, Payload: (Ping{ID: 71}).MarshalBinary()},
		},
		{
			name:       "zero submission ID",
			submission: LinkSubmission{ConnectionID: 41, Payload: requestPayload},
			want:       ErrInvalidLinkSubmission,
		},
		{
			name:       "zero connection ID",
			submission: LinkSubmission{SubmissionID: 4, Payload: requestPayload},
			want:       ErrInvalidLinkSubmission,
		},
		{
			name:       "mismatched connection ID",
			submission: LinkSubmission{SubmissionID: 5, ConnectionID: 42, Payload: requestPayload},
			want:       ErrInvalidLinkSubmission,
		},
		{
			name:       "ping connection ID",
			submission: LinkSubmission{SubmissionID: 6, ConnectionID: 41, Payload: (Ping{ID: 71}).MarshalBinary()},
			want:       ErrInvalidLinkSubmission,
		},
		{
			name:       "wrong direction",
			submission: LinkSubmission{SubmissionID: 7, ConnectionID: 41, Payload: (CloseExternal{ConnectionID: 41}).MarshalBinary()},
			want:       ErrUnexpectedLinkRPC,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.submission.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Validate error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseLinkEvent(t *testing.T) {
	answerPayload, err := (ProxyAnswer{
		Flags:        ProxyAnswerFlagFlush,
		ConnectionID: 41,
		Packet:       []byte{1, 2, 3, 4},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	tests := []struct {
		name    string
		payload []byte
		check   func(*testing.T, LinkEvent)
	}{
		{
			name:    "proxy answer",
			payload: answerPayload,
			check: func(t *testing.T, event LinkEvent) {
				if event.Kind != LinkEventProxyAnswer || event.ConnectionID != 41 ||
					event.AnswerFlags != ProxyAnswerFlagFlush || event.ByteSize() != len(answerPayload) {
					t.Fatalf("event = %+v", event)
				}
			},
		},
		{
			name:    "simple ack",
			payload: (SimpleAck{ConnectionID: 42, ConfirmKey: 0x01020304}).MarshalBinary(),
			check: func(t *testing.T, event LinkEvent) {
				if event.Kind != LinkEventSimpleAck || event.ConnectionID != 42 ||
					event.ConfirmKey != 0x01020304 || event.ByteSize() != SimpleAckPayloadSize {
					t.Fatalf("event = %+v", event)
				}
			},
		},
		{
			name:    "close external",
			payload: (CloseExternal{ConnectionID: 43}).MarshalBinary(),
			check: func(t *testing.T, event LinkEvent) {
				if event.Kind != LinkEventCloseExternal || event.ConnectionID != 43 || event.ByteSize() != ClosePayloadSize {
					t.Fatalf("event = %+v", event)
				}
			},
		},
		{
			name:    "ping",
			payload: (Ping{ID: 44}).MarshalBinary(),
			check: func(t *testing.T, event LinkEvent) {
				if event.Kind != LinkEventPing || event.KeepaliveID != 44 || event.ByteSize() != KeepalivePayloadSize {
					t.Fatalf("event = %+v", event)
				}
			},
		},
		{
			name:    "pong",
			payload: (Pong{ID: 45}).MarshalBinary(),
			check: func(t *testing.T, event LinkEvent) {
				if event.Kind != LinkEventPong || event.KeepaliveID != 45 || event.ByteSize() != KeepalivePayloadSize {
					t.Fatalf("event = %+v", event)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := parseLinkEvent(test.payload)
			if err != nil {
				t.Fatalf("parseLinkEvent: %v", err)
			}
			test.check(t, event)
		})
	}
}

func TestParseLinkEventRejectsWrongDirection(t *testing.T) {
	if _, err := parseLinkEvent((CloseConnection{ConnectionID: 41}).MarshalBinary()); !errors.Is(err, ErrUnexpectedLinkRPC) {
		t.Fatalf("parseLinkEvent error = %v", err)
	}
}

func TestLinkFormattingRedactsPayloads(t *testing.T) {
	submission := LinkSubmission{
		SubmissionID: 123456,
		ConnectionID: 654321,
		Payload:      bytes.Repeat([]byte{218}, 32),
	}
	event := LinkEvent{
		Kind:         LinkEventProxyAnswer,
		ConnectionID: 654321,
		AnswerFlags:  ProxyAnswerFlagFlush,
		Packet:       bytes.Repeat([]byte{219}, 32),
	}
	type enclosing struct {
		Submission LinkSubmission
		Event      LinkEvent
	}
	for name, value := range map[string]any{
		"submission value":   submission,
		"submission pointer": &submission,
		"event value":        event,
		"event pointer":      &event,
		"enclosing value":    enclosing{Submission: submission, Event: event},
		"enclosing pointer":  &enclosing{Submission: submission, Event: event},
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if !strings.Contains(output, "redacted") || !strings.Contains(output, "654321") {
				t.Fatalf("%s with %s omitted redaction or routing ID: %s", name, format, output)
			}
			for _, marker := range []string{"218 218", "219 219", "dadadada", "dbdbdbdb"} {
				if strings.Contains(strings.ToLower(output), marker) {
					t.Fatalf("%s with %s leaked marker %q: %s", name, format, marker, output)
				}
			}
		}
	}

	for name, value := range map[string]any{
		"nil submission": (*LinkSubmission)(nil),
		"nil event":      (*LinkEvent)(nil),
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, "218 218") || strings.Contains(output, "219 219") {
				t.Fatalf("%s with %s leaked data: %s", name, format, output)
			}
		}
	}
}

func TestLinkSubmissionByteSize(t *testing.T) {
	for _, size := range []int{0, 1, 4096, MaxMEFrameSize} {
		submission := LinkSubmission{Payload: make([]byte, size)}
		if got := submission.ByteSize(); got != size {
			t.Fatalf("ByteSize = %d, want %d", got, size)
		}
	}
}
