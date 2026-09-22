// Package producer wraps go-nats to emit audit-events for target-service.
// Events emitted: target_verified, scope_expanded, verification_failed (03 §2, 02 §6)
// plus the admin-panel write events admin.target.* (plans/10-ADMIN-PANEL.md §3).
// All events use the canonical AuditEvent envelope from go-events (audit.go).
package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"target-service/internal/model"
	"time"

	goevents "github.com/paaavkata/go-events"
	logger "github.com/paaavkata/go-logger"
	gonats "github.com/paaavkata/go-nats"

	"github.com/google/uuid"
)

const (
	AuditTopic = "audit-events"

	EventTypeTargetVerified     = "target.verified"
	EventTypeVerificationFailed = "target.verification_failed"
	EventTypeScopeExpanded      = "target.scope_expanded"

	// Admin-panel writes (plans/10-ADMIN-PANEL.md §3). Actor is the admin's X-User-Id.
	EventTypeAdminTargetCreated    = "admin.target.created"
	EventTypeAdminTargetAuthorized = "admin.target.authorized"
	EventTypeAdminTargetRevoked    = "admin.target.revoked"
	EventTypeAdminTargetDeleted    = "admin.target.deleted"

	ServiceName = "target-service"
)

// AuditProducer emits AuditEvent messages to the audit-events NATS JetStream topic.
type AuditProducer struct {
	urls     []string
	clientID string

	mu        sync.Mutex
	producers map[string]*gonats.Producer

	wg sync.WaitGroup
}

// NewAuditProducer constructs a NATS JetStream-backed producer for the audit-events topic.
func NewAuditProducer(urls []string, clientID string) (*AuditProducer, error) {
	return &AuditProducer{
		urls:      urls,
		clientID:  clientID,
		producers: make(map[string]*gonats.Producer),
	}, nil
}

// producerFor returns the cached gonats.Producer for the given topic,
// creating it on first use.
func (ap *AuditProducer) producerFor(topic string) (*gonats.Producer, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	if p, ok := ap.producers[topic]; ok {
		return p, nil
	}

	p, err := gonats.NewProducer(&gonats.ProducerConfig{
		URLs:     ap.urls,
		ClientID: ap.clientID,
		Topic:    topic,
	})
	if err != nil {
		return nil, err
	}
	ap.producers[topic] = p
	return p, nil
}

// Close waits for pending fire-and-forget messages and closes all producers.
func (ap *AuditProducer) Close() {
	ap.wg.Wait()

	ap.mu.Lock()
	defer ap.mu.Unlock()

	for _, p := range ap.producers {
		p.Close()
	}
	logger.Info("audit NATS producer closed")
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

// adminActor builds the AuditActor for an admin-panel write: actor
// {type:"user", uid:<admin X-User-Id>} per plans/10-ADMIN-PANEL.md §2.
func adminActor(adminUserID int64) goevents.AuditActor {
	return goevents.AuditActor{Type: goevents.ActorTypeUser, UID: strconv.FormatInt(adminUserID, 10)}
}

func adminTargetMeta(target *model.Target) map[string]interface{} {
	meta := map[string]interface{}{
		"target_uid": target.UID,
		"kind":       target.Kind,
		"value":      target.Value,
		"user_id":    target.UserID,
		"source":     target.Source,
		"status":     target.Status,
	}
	if target.Label != nil {
		meta["label"] = *target.Label
	}
	return meta
}

// EmitAdminTargetCreated emits admin.target.created after an admin registers a
// program target. evidence is the recorded program (stored verbatim on the
// authorization row).
func (ap *AuditProducer) EmitAdminTargetCreated(ctx context.Context, appID string, adminUserID int64, target *model.Target, auth *model.Authorization) error {
	meta := adminTargetMeta(target)
	if auth != nil {
		meta["authorization_uid"] = auth.UID
		meta["method"] = auth.Method
		meta["expires_at"] = auth.ExpiresAt
		meta["evidence"] = auth.Evidence
	}
	return ap.emit(ctx, appID, EventTypeAdminTargetCreated,
		fmt.Sprintf("admin %d created program target %s (%s)", adminUserID, target.UID, target.Value),
		target.UID,
		adminActor(adminUserID),
		&goevents.AuditTarget{Type: "target", UID: target.UID},
		"INFO",
		meta,
	)
}

// EmitAdminTargetAuthorized emits admin.target.authorized after an admin manually
// marks a target verified (method=manual, or a pending challenge confirmed).
func (ap *AuditProducer) EmitAdminTargetAuthorized(ctx context.Context, appID string, adminUserID int64, target *model.Target, auth *model.Authorization, note string) error {
	meta := adminTargetMeta(target)
	meta["note"] = note
	if auth != nil {
		meta["authorization_uid"] = auth.UID
		meta["method"] = auth.Method
		meta["expires_at"] = auth.ExpiresAt
	}
	return ap.emit(ctx, appID, EventTypeAdminTargetAuthorized,
		fmt.Sprintf("admin %d manually authorized target %s (%s)", adminUserID, target.UID, target.Value),
		target.UID,
		adminActor(adminUserID),
		&goevents.AuditTarget{Type: "target", UID: target.UID},
		"WARNING",
		meta,
	)
}

// EmitAdminTargetRevoked emits admin.target.revoked (kill switch).
func (ap *AuditProducer) EmitAdminTargetRevoked(ctx context.Context, appID string, adminUserID int64, target *model.Target, reason string, expired int64) error {
	meta := adminTargetMeta(target)
	meta["reason"] = reason
	meta["authorizations_expired"] = expired
	return ap.emit(ctx, appID, EventTypeAdminTargetRevoked,
		fmt.Sprintf("admin %d revoked target %s (%s): %s", adminUserID, target.UID, target.Value, reason),
		target.UID,
		adminActor(adminUserID),
		&goevents.AuditTarget{Type: "target", UID: target.UID},
		"WARNING",
		meta,
	)
}

// EmitAdminTargetDeleted emits admin.target.deleted.
func (ap *AuditProducer) EmitAdminTargetDeleted(ctx context.Context, appID string, adminUserID int64, target *model.Target) error {
	return ap.emit(ctx, appID, EventTypeAdminTargetDeleted,
		fmt.Sprintf("admin %d deleted target %s (%s)", adminUserID, target.UID, target.Value),
		target.UID,
		adminActor(adminUserID),
		&goevents.AuditTarget{Type: "target", UID: target.UID},
		"WARNING",
		adminTargetMeta(target),
	)
}

// emit builds the canonical AuditEvent envelope and sends it to NATS JetStream.
// partitionKey is carried in the NATS message header for routing context.
// A nil receiver is a no-op so services can be constructed without NATS in tests.
func (ap *AuditProducer) emit(
	ctx context.Context,
	appID, eventType, message, partitionKey string,
	actor goevents.AuditActor,
	target *goevents.AuditTarget,
	severity string,
	metadata map[string]interface{},
) error {
	if ap == nil {
		return nil
	}
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

	p, err := ap.producerFor(AuditTopic)
	if err != nil {
		logger.Errorf("auditProducer.emit %s: get producer: %v", eventType, err)
		return fmt.Errorf("auditProducer.emit %s: %w", eventType, err)
	}

	if err := p.SendMessageWithContext(ctx, partitionKey, event); err != nil {
		logger.Errorf("auditProducer.emit %s: %v", eventType, err)
		return fmt.Errorf("auditProducer.emit %s: %w", eventType, err)
	}
	return nil
}
