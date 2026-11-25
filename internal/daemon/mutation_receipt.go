package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/policy"
	"flowgate/internal/uploadshape"
	"sync"
)

const MutationReceiptCapability = "mutation-receipts-v1"

// Receipts are bounded and live for the daemon generation. Never evict a
// receipt to run another mutation: an old ID must not become executable again.
const maxMutationReceipts = 1024
const maxMutationReceiptBytes = 8 << 20

type MutationReceipt struct {
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	State     string          `json:"state"`
	Result    json.RawMessage `json:"result,omitempty"`
}

type mutationResult struct {
	Error         string                `json:"error,omitempty"`
	ErrorCode     string                `json:"error_code,omitempty"`
	SavedRule     *policy.Rule          `json:"saved_rule,omitempty"`
	DeletedRule   *DeletedRule          `json:"deleted_rule,omitempty"`
	DeletedRules  []DeletedRule         `json:"deleted_rules,omitempty"`
	ScopePreview  string                `json:"scope_preview,omitempty"`
	Decision      *Event                `json:"decision,omitempty"`
	Pair          *PairDecision         `json:"pair,omitempty"`
	Settled       []SettledRequest      `json:"settled,omitempty"`
	ProcessLease  *ProcessLease         `json:"process_lease,omitempty"`
	RequestEnded  bool                  `json:"request_ended,omitempty"`
	UploadShaping *uploadshape.Snapshot `json:"upload_shaping,omitempty"`
}

type mutationKey struct {
	id    string
	uid   uint32
	admin bool
}

type mutationEntry struct {
	fingerprint [32]byte
	receipt     MutationReceipt
}

type mutationReceipts struct {
	mu      sync.Mutex
	entries map[mutationKey]*mutationEntry
	bytes   int
}

func receiptOperation(operation string) bool {
	switch operation {
	case "rule-save", "rule", "rule-delete", "application-rule-delete",
		"observed-rule-save", "request-rule-save", "zone-rule-save", "endpoint-rule-save",
		"zone-migration-save", "decide", "decide-pair", "request-for-a-while", "upload-configure":
		return true
	}
	return false
}

// beginMutation returns handled=true for a status lookup, replay or refusal.
// The normal handler still authorizes and executes every new mutation.
func (e *Engine) beginMutation(q Request, r *Response, admin bool) (handled bool, reservation *mutationEntry) {
	status := q.Operation == "mutation-status"
	if q.MutationID == "" && !status {
		return false, nil
	}
	if r.ReadOnly || e.Mode == "host-monitor" || !e.activityAuthorized(r.PeerUID) {
		r.ErrorCode, r.Error = "read_only", "Mutation receipts require an authorized primary endpoint"
		return true, nil
	}
	decoded, err := hex.DecodeString(q.MutationID)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != q.MutationID || (!status && !receiptOperation(q.Operation)) {
		r.ErrorCode, r.Error = "invalid_request", "Supported mutation and 32 lowercase hexadecimal mutation_id required"
		return true, nil
	}
	if q.Generation != e.Generation {
		r.ErrorCode, r.Error = "generation_conflict", "Daemon generation changed; read authoritative state before any new mutation"
		return true, nil
	}
	var fingerprint [32]byte
	if !status {
		body, err := json.Marshal(q)
		if err != nil {
			r.ErrorCode, r.Error = "invalid_request", "Invalid mutation document"
			return true, nil
		}
		fingerprint = sha256.Sum256(body)
	}
	c := &e.mutationReceipts
	c.mu.Lock()
	defer c.mu.Unlock()
	key := mutationKey{q.MutationID, r.PeerUID, admin}
	if previous := c.entries[key]; previous != nil {
		if !status && previous.fingerprint != fingerprint {
			r.ErrorCode, r.Error = "mutation_conflict", "Mutation ID already belongs to a different request"
			return true, nil
		}
		receipt := previous.receipt
		r.MutationReceipt, r.Replayed = &receipt, !status
		return true, nil
	}
	if status {
		r.ErrorCode, r.Error = "not_found", "No mutation receipt for this principal and generation"
		return true, nil
	}
	if len(c.entries) >= maxMutationReceipts || c.bytes >= maxMutationReceiptBytes {
		r.ErrorCode, r.Error = "limit_exceeded", "Mutation receipt capacity reached; no operation sent"
		return true, nil
	}
	if c.entries == nil {
		c.entries = make(map[mutationKey]*mutationEntry)
	}
	entry := &mutationEntry{fingerprint: fingerprint, receipt: MutationReceipt{ID: q.MutationID, Operation: q.Operation, State: "pending"}}
	c.entries[key] = entry
	return false, entry
}

// Save the operation result before list publication and the socket write.
// A failure in either of those steps cannot erase an acknowledged mutation.
func (e *Engine) completeMutation(entry *mutationEntry, r *Response) {
	if entry == nil {
		return
	}
	result, err := json.Marshal(mutationResult{
		Error: r.Error, ErrorCode: r.ErrorCode, SavedRule: r.SavedRule,
		DeletedRule: r.DeletedRule, DeletedRules: r.DeletedRules,
		ScopePreview: r.ScopePreview, Decision: r.Decision, Pair: r.Pair,
		Settled: r.Settled, ProcessLease: r.ProcessLease, RequestEnded: r.RequestEnded,
		UploadShaping: r.UploadShaping,
	})
	c := &e.mutationReceipts
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil || len(result) > maxMutationReceiptBytes-c.bytes {
		entry.receipt.State = "unavailable"
	} else {
		entry.receipt.State = "completed"
		entry.receipt.Result = result
		c.bytes += len(result)
	}
	receipt := entry.receipt
	r.MutationReceipt = &receipt
}
