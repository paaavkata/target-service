// Package producer wraps go-kafka to emit audit-events for target-service.
// Events emitted: target_verified, scope_expanded, verification_failed (03 §2, 02 §6).
// All events use the canonical AuditEvent envelope from go-events (audit.go).
package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"target-service/internal/model"
	"time"

	goevents "github.com/paaavkata/go-events"
	gokafka "github.com/paaavkata/go-kafka"
	logger "github.com/paaavkata/go-logger"

	"github.com/google/uuid"
)

const (
	AuditTopic = "audit-events"

	EventTypeTargetVerified     = "target.verified"
	EventTypeVerificationFailed = "target.verification_failed"
	EventTypeScopeExpanded      = "target.scope_expanded"

	ServiceName = "target-service"
)

// AuditProducer emits AuditEvent messages to the audit-events Kafka topic.
type AuditProducer struct {
	producer *gokafka.Producer
}

// NewAuditProducer constructs a Sarama-backed producer for the audit-events topic.
func NewAuditProducer(brokers []string, clientID string) (*AuditProducer, error) {
	cfg := &gokafka.ProducerConfig{
		Brokers:  brokers,
		ClientID: clientID,
		Topic:    AuditTopic,
	}
	p, err := gokafka.NewProducer(cfg)
	if err != nil {
		return nil, fmt.Errorf("auditProducer: %w", err)
	}
	return &AuditProducer{producer: p}, nil
}

// Close flushes and closes the underlying Sarama producer.
func (ap *AuditProducer) Close() {
	if err := ap.producer.Close(); err != nil {
		logger.Errorf("auditProducer.Close: %v", err)
	}
}

// EmitTargetVerified emits a target.verified audit event.
func (ap *AuditProducer) EmitTargetVerified(ctx context.Context, appID string, target *model.Target) error {
	meta := map[string]interface{}{
		"target_uid": target.UID,
		"kind":       target.Kind,
		"value":      target.Value,
		"user_id":    target.UserID,
	}
	return ap.emit(ctx, appID, EventTypeTargetVerified,
		fmt.Sprintf("target %s verified", target.UID),
		target.UID,
		goevents.AuditActor{Type: goevents.ActorTypeSystem, UID: ServiceName},
		&goevents.AuditTarget{Type: "target", UID: target.UID},
		"INFO",
		meta,
	)
}

// EmitVerificationFailed emits a target.verification_failed audit event.
func (ap *AuditProducer) EmitVerificationFailed(ctx context.Context, appID string, target *model.Target, reason string) error {
	meta := map[string]interface{}{
		"target_uid": target.UID,
		"kind":       target.Kind,
		"value":      target.Value,
		"user_id":    target.UserID,
		"reason":     reason,
	}
	return ap.emit(ctx, appID, EventTypeVerificationFailed,
		fmt.Sprintf("verification failed for target %s: %s", target.UID, reason),
		target.UID,
		goevents.AuditActor{Type: goevents.ActorTypeSystem, UID: ServiceName},
		&goevents.AuditTarget{Type: "target", UID: target.UID},
		"WARNING",
		meta,
	)
}

// EmitScopeExpanded emits a target.scope_expanded audit event when new assets are added.
func (ap *AuditProducer) EmitScopeExpanded(ctx context.Context, appID string, target *model.Target, assetCount int) error {
	meta := map[string]interface{}{
		"target_uid":  target.UID,
		"user_id":     target.UserID,
		"asset_count": assetCount,
	}
	return ap.emit(ctx, appID, EventTypeScopeExpanded,
		fmt.Sprintf("%d assets added to inventory for target %s", assetCount, target.UID),
		target.UID,
		goevents.AuditActor{Type: goevents.ActorTypeSystem, UID: ServiceName},
		&goevents.AuditTarget{Type: "target", UID: target.UID},
		"INFO",
		meta,
	)
}

// emit builds the canonical AuditEvent envelope and sends it to Kafka.
// partitionKey is used as the Kafka message key for consistent partition routing.
func (ap *AuditProducer) emit(
	ctx context.Context,
	appID, eventType, message, partitionKey string,
	actor goevents.AuditActor,
	target *goevents.AuditTarget,
	severity string,
	metadata map[string]interface{},
) error {
	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("auditProducer.emit %s: marshal metadata: %w", eventType, err)
	}

	// Extract correlation-id from context if present.
	correlationID := ""
	if v := ctx.Value("correlation_id"); v != nil {
		if s, ok := v.(string); ok {
			correlationID = s
		}
	}

	event := &goevents.AuditEvent{
		Version:   1,
		UID:       uuid.New().String(),
		AppID:     appID,
		Type:      eventType,
		Service:   ServiceName,
		Timestamp: time.Now().UTC(),
		Trace:     correlationID,
		Actor:     actor,
		Severity:  severity,
		Target:    target,
		Message:   message,
		Metadata:  json.RawMessage(metaBytes),
	}

	if err := event.Validate(); err != nil {
		return fmt.Errorf("auditProducer.emit %s: invalid event: %w", eventType, err)
	}

	if err := ap.producer.SendMessageWithContext(ctx, partitionKey, event); err != nil {
		logger.Errorf("auditProducer.emit %s: %v", eventType, err)
		return fmt.Errorf("auditProducer.emit %s: %w", eventType, err)
	}
	return nil
}
