// Package producer wraps go-kafka to emit audit-events for target-service.
// Events emitted: target_verified, scope_expanded, verification_failed (03 §2, 02 §6).
package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"target-service/internal/model"
	"time"

	gokafka "github.com/paaavkata/go-kafka"
	logger "github.com/paaavkata/go-logger"

	"github.com/google/uuid"
)

const (
	AuditTopic = "audit-events"

	EventTypeTargetVerified     = "target.verified"
	EventTypeVerificationFailed = "target.verification_failed"
	EventTypeScopeExpanded      = "target.scope_expanded"
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
	return ap.emit(ctx, appID, EventTypeTargetVerified, "target-service", fmt.Sprintf("target %s verified", target.UID), target.UID, map[string]interface{}{
		"target_uid": target.UID,
		"kind":       target.Kind,
		"value":      target.Value,
		"user_id":    target.UserID,
	})
}

// EmitVerificationFailed emits a target.verification_failed audit event.
func (ap *AuditProducer) EmitVerificationFailed(ctx context.Context, appID string, target *model.Target, reason string) error {
	return ap.emit(ctx, appID, EventTypeVerificationFailed, "target-service", fmt.Sprintf("verification failed for target %s: %s", target.UID, reason), target.UID, map[string]interface{}{
		"target_uid": target.UID,
		"kind":       target.Kind,
		"value":      target.Value,
		"user_id":    target.UserID,
		"reason":     reason,
	})
}

// EmitScopeExpanded emits a target.scope_expanded audit event when new assets are added.
func (ap *AuditProducer) EmitScopeExpanded(ctx context.Context, appID string, target *model.Target, assetCount int) error {
	return ap.emit(ctx, appID, EventTypeScopeExpanded, "target-service", fmt.Sprintf("%d assets added to inventory for target %s", assetCount, target.UID), target.UID, map[string]interface{}{
		"target_uid":  target.UID,
		"user_id":     target.UserID,
		"asset_count": assetCount,
	})
}

// emit builds and sends a canonical AuditEvent.
func (ap *AuditProducer) emit(ctx context.Context, appID, eventType, service, message, partitionKey string, metadata map[string]interface{}) error {
	metaBytes, _ := json.Marshal(metadata)

	event := map[string]interface{}{
		"version":   1,
		"uid":       uuid.New().String(),
		"app_id":    appID,
		"type":      eventType,
		"service":   service,
		"timestamp": time.Now().UTC(),
		"message":   message,
		"metadata":  json.RawMessage(metaBytes),
	}

	if err := ap.producer.SendMessageWithContext(ctx, partitionKey, event); err != nil {
		logger.Errorf("auditProducer.emit %s: %v", eventType, err)
		return fmt.Errorf("auditProducer.emit %s: %w", eventType, err)
	}
	return nil
}
