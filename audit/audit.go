// Package audit publishes IAM authorization failures to the compliance stream.
package audit

import (
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grasp-labs/ds-event-stream-go-sdk/models"
	"github.com/grasp-labs/ds-go-iam-middleware/iam"
)

type Producer interface {
	Send(context.Context, string, any) error
}

type Publisher struct {
	producer Producer
	topic    string
	source   string
}

func New(producer Producer, topic, source string) (*Publisher, error) {
	if producer == nil || strings.TrimSpace(topic) == "" || strings.TrimSpace(source) == "" {
		return nil, errors.New("audit: producer, topic, and source are required")
	}
	return &Publisher{producer: producer, topic: topic, source: source}, nil
}

// Event snapshots a failed authorization check and its HTTP response. Identity
// must come from the verified principal, never from unverified token claims.
type Event struct {
	TenantID, RequestID, SessionID       uuid.UUID
	Subject, Path, UserAgent, RemoteAddr string
	Action, Resource, Reason             string
	Message                              string
	StatusCode                           int
	Err                                  error
}

type payload struct {
	StatusCode int     `json:"status_code"`
	Subject    string  `json:"subject"`
	Error      *string `json:"error"`
	Path       string  `json:"path"`
	UserAgent  string  `json:"user_agent"`
	RemoteAddr string  `json:"remote_addr"`
	Action     string  `json:"action"`
	Resource   string  `json:"resource,omitempty"`
	Reason     string  `json:"reason"`
}

// Publish sends one failure event, allowing up to three seconds even if the
// request was canceled. The caller decides whether to send asynchronously.
func (p *Publisher) Publish(ctx context.Context, event Event) error {
	if strings.TrimSpace(event.Action) == "" || event.StatusCode < 400 || event.StatusCode > 599 {
		return errors.New("audit: action and failed HTTP status are required")
	}
	var errorText *string
	if event.Err != nil {
		errorText = new(event.Err.Error())
	}
	reason := event.Reason
	if reason == "" {
		reason = "access denied"
		if errorText != nil {
			reason = *errorText
		}
	}
	body := payload{
		StatusCode: event.StatusCode, Subject: event.Subject, Error: errorText,
		Path: event.Path, UserAgent: event.UserAgent, RemoteAddr: event.RemoteAddr,
		Action: event.Action, Resource: event.Resource, Reason: reason,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("audit: encode payload: %w", err)
	}
	// MD5 is the existing event-envelope checksum, not a security signature.
	checksum := md5.Sum(encoded)
	eventType := "authz.error"
	if event.Err == nil || errors.Is(event.Err, iam.ErrAccessDenied) ||
		errors.Is(event.Err, iam.ErrNoPrincipal) || errors.Is(event.Err, iam.ErrTokenRejected) {
		eventType = "authz.denied"
	}
	if event.RequestID == uuid.Nil {
		event.RequestID = uuid.New()
	}
	if event.SessionID == uuid.Nil {
		event.SessionID = uuid.New()
	}
	var message *string
	if event.Message != "" {
		message = new(event.Message)
	}
	envelope := models.EventJson{
		Id: uuid.New(), TenantId: event.TenantID, RequestId: event.RequestID, SessionId: event.SessionID,
		Timestamp: time.Now().UTC(), EventType: eventType, EventSource: p.source,
		CreatedBy: cmp.Or(event.Subject, p.source), Metadata: map[string]string{},
		Md5Hash: hex.EncodeToString(checksum[:]), Payload: body, Message: message,
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	return p.producer.Send(ctx, p.topic, envelope)
}
