package audit_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grasp-labs/ds-event-stream-go-sdk/models"
	"github.com/grasp-labs/ds-go-iam-middleware/audit"
	"github.com/grasp-labs/ds-go-iam-middleware/iam"
)

type producerFunc func(context.Context, string, any) error

func (f producerFunc) Send(ctx context.Context, topic string, event any) error {
	return f(ctx, topic, event)
}

func TestPublishEventContract(t *testing.T) {
	const topic = "ds.monitor.compliance.audit.created.v1"
	const source = "ds.core.file.v1"
	for _, tt := range []struct {
		name, eventType string
		err             error
		status          int
	}{
		{"policy denial", "authz.denied", nil, 403},
		{"closed filter", "authz.denied", iam.ErrAccessDenied, 403},
		{"missing principal", "authz.denied", iam.ErrNoPrincipal, 401},
		{"wrapped rejected token", "authz.denied", errors.Join(iam.ErrPolicyResolution, iam.ErrTokenRejected), 401},
		{"unavailable policy", "authz.error", errors.Join(iam.ErrPolicyResolution, iam.ErrPolicySourceUnavailable), 503},
		{"principal rejected", "authz.error", iam.ErrPrincipalRejected, 500},
		{"missing middleware", "authz.error", iam.ErrNoMiddleware, 500},
		{"converter error", "authz.error", errors.New("unsupported resource pattern"), 500},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := audit.Event{
				TenantID: uuid.New(), RequestID: uuid.New(), SessionID: uuid.New(),
				Subject: "user@example.com", Path: "/file/:id/", UserAgent: "audit-test", RemoteAddr: "192.0.2.1:1234",
				Action: "file:getFile", Resource: "crn:tenant:*:file::file:reports/a.pdf", Reason: "matched policy",
				StatusCode: tt.status, Err: tt.err,
			}
			var encoded []byte
			publisher, err := audit.New(producerFunc(func(_ context.Context, gotTopic string, value any) error {
				if gotTopic != topic {
					t.Errorf("topic = %q, want %q", gotTopic, topic)
				}
				var err error
				encoded, err = json.Marshal(value)
				return err
			}), topic, source)
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			if err := publisher.Publish(t.Context(), event); err != nil {
				t.Fatal(err)
			}
			var envelope models.EventJson
			if err := json.Unmarshal(encoded, &envelope); err != nil {
				t.Fatalf("event does not satisfy SDK envelope: %v", err)
			}
			if envelope.Id == uuid.Nil || envelope.Id == event.RequestID || envelope.TenantId != event.TenantID ||
				envelope.RequestId != event.RequestID || envelope.SessionId != event.SessionID {
				t.Errorf("incorrect event IDs: %+v", envelope)
			}
			if envelope.EventType != tt.eventType || envelope.EventSource != source || envelope.CreatedBy != event.Subject {
				t.Errorf("incorrect event identity: %+v", envelope)
			}
			if envelope.Metadata == nil || len(envelope.Metadata) != 0 {
				t.Errorf("metadata = %#v, want empty object", envelope.Metadata)
			}
			if envelope.Timestamp.Before(before) || envelope.Timestamp.After(time.Now()) || envelope.Timestamp.Location() != time.UTC {
				t.Errorf("timestamp = %v, want current UTC time", envelope.Timestamp)
			}
			var wantError any
			if tt.err != nil {
				wantError = tt.err.Error()
			}
			wantPayload := map[string]any{
				"status_code": float64(tt.status), "subject": event.Subject, "error": wantError,
				"path": event.Path, "user_agent": event.UserAgent, "remote_addr": event.RemoteAddr,
				"action": event.Action, "resource": event.Resource, "reason": event.Reason,
			}
			if !reflect.DeepEqual(envelope.Payload, wantPayload) {
				t.Errorf("payload = %#v, want %#v", envelope.Payload, wantPayload)
			}
			var raw struct {
				Payload json.RawMessage `json:"payload"`
			}
			if err := json.Unmarshal(encoded, &raw); err != nil {
				t.Fatal(err)
			}
			hash := md5.Sum(raw.Payload)
			if envelope.Md5Hash != hex.EncodeToString(hash[:]) {
				t.Errorf("checksum = %q, want checksum of serialized payload", envelope.Md5Hash)
			}
		})
	}
}

func TestPublishUnknownIdentityAndCollectionScope(t *testing.T) {
	var events []models.EventJson
	publisher, err := audit.New(producerFunc(func(_ context.Context, _ string, value any) error {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		var event models.EventJson
		if err := json.Unmarshal(data, &event); err != nil {
			return err
		}
		events = append(events, event)
		return nil
	}), "audit-topic", "ds.core.file.v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, cause := range []error{nil, iam.ErrNoPrincipal} {
		if err := publisher.Publish(t.Context(), audit.Event{Action: "file:listFiles", StatusCode: 401, Err: cause}); err != nil {
			t.Fatal(err)
		}
	}
	for i, event := range events {
		if event.TenantId != uuid.Nil || event.CreatedBy != "ds.core.file.v1" || event.RequestId == uuid.Nil || event.SessionId == uuid.Nil {
			t.Errorf("incorrect fallback identity: %+v", event)
		}
		body := event.Payload.(map[string]any)
		if _, exists := body["resource"]; exists {
			t.Error("collection event must omit resource")
		}
		wantReason := "access denied"
		if i == 1 {
			wantReason = iam.ErrNoPrincipal.Error()
		}
		if body["reason"] != wantReason || body["subject"] != "" {
			t.Errorf("incorrect fallback payload: %#v", body)
		}
	}
	if events[0].Id == events[1].Id {
		t.Error("separate events reused the same ID")
	}
}

func TestPublishDetachesCancellationAndReturnsSendError(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, "request-value"))
	cancel()
	wantErr := errors.New("Kafka unavailable")
	publisher, err := audit.New(producerFunc(func(ctx context.Context, _ string, _ any) error {
		if ctx.Err() != nil || ctx.Value(contextKey{}) != "request-value" {
			t.Errorf("send context lost request value or retained cancellation: %v", ctx.Err())
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 3*time.Second {
			t.Errorf("send deadline = %v, want timeout within three seconds", deadline)
		}
		return wantErr
	}), "audit-topic", "ds.core.file.v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(ctx, audit.Event{Action: "file:getFile", StatusCode: 403}); !errors.Is(err, wantErr) {
		t.Errorf("Publish error = %v, want %v", err, wantErr)
	}
}

func TestInvalidConfigurationAndEvent(t *testing.T) {
	producer := producerFunc(func(context.Context, string, any) error {
		t.Error("invalid event was sent")
		return nil
	})
	for _, config := range []struct {
		producer      audit.Producer
		topic, source string
	}{
		{nil, "topic", "source"},
		{producer, " \t", "source"},
		{producer, "topic", ""},
	} {
		if _, err := audit.New(config.producer, config.topic, config.source); err == nil {
			t.Error("New accepted invalid configuration")
		}
	}
	publisher, err := audit.New(producer, "topic", "source")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []audit.Event{
		{Action: "", StatusCode: 403},
		{Action: "file:getFile", StatusCode: 200},
		{Action: "file:getFile", StatusCode: 600},
	} {
		t.Run(fmt.Sprintf("action=%s/status=%d", event.Action, event.StatusCode), func(t *testing.T) {
			if err := publisher.Publish(t.Context(), event); err == nil {
				t.Error("Publish accepted invalid event")
			}
		})
	}
}
