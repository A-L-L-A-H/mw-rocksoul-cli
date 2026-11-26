package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// SessionStore persists coding agent sessions and message histories without coupling to external database engines.
type SessionStore interface {
	InsertSession(ctx context.Context, session Session) error
	ListSessions(ctx context.Context, limit int) ([]Session, error)
	GetSession(ctx context.Context, sessionID string) (Session, error)
	UpdateSession(ctx context.Context, session Session) error
	DeleteSession(ctx context.Context, sessionID string) error
	AppendMessage(ctx context.Context, sessionID string, msg Message) (Message, error)
	ListMessages(ctx context.Context, sessionID string) ([]Message, error)
	ReplaceMessages(ctx context.Context, sessionID string, messages []Message, updatedAt string) error
	AddTelemetry(ctx context.Context, sessionID string, tokensIn, tokensOut, rtkSaved int64, updatedAt string) error
	SetStatus(ctx context.Context, sessionID, status, updatedAt string) error
}

type storedSessionEntry struct {
	Session Session
	Order   uint64
}

// MemoryStore is a concurrency-safe in-memory SessionStore implementation.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*storedSessionEntry
	messages map[string][]Message
	nextSeq  uint64
}

// NewMemoryStore creates an empty in-memory SessionStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*storedSessionEntry),
		messages: make(map[string][]Message),
	}
}

func (m *MemoryStore) InsertSession(_ context.Context, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextSeq++
	copied := session
	m.sessions[session.ID] = &storedSessionEntry{Session: copied, Order: m.nextSeq}
	if _, exists := m.messages[session.ID]; !exists {
		m.messages[session.ID] = make([]Message, 0)
	}
	return nil
}

func (m *MemoryStore) ListSessions(_ context.Context, limit int) ([]Session, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries := make([]storedSessionEntry, 0, len(m.sessions))
	for _, entry := range m.sessions {
		entries = append(entries, *entry)
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].Session.UpdatedAt != entries[right].Session.UpdatedAt {
			return entries[left].Session.UpdatedAt > entries[right].Session.UpdatedAt
		}
		return entries[left].Order > entries[right].Order
	})

	if len(entries) > limit {
		entries = entries[:limit]
	}
	result := make([]Session, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Session)
	}
	return result, nil
}

func (m *MemoryStore) GetSession(_ context.Context, sessionID string) (Session, error) {
	cleanID := strings.TrimSpace(sessionID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, exists := m.sessions[cleanID]
	if !exists {
		return Session{}, ErrSessionNotFound
	}
	return entry.Session, nil
}

func (m *MemoryStore) UpdateSession(_ context.Context, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.sessions[session.ID]
	if !exists {
		return ErrSessionNotFound
	}
	m.nextSeq++
	entry.Session = session
	entry.Order = m.nextSeq
	return nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, sessionID string) error {
	cleanID := strings.TrimSpace(sessionID)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[cleanID]; !exists {
		return ErrSessionNotFound
	}
	delete(m.sessions, cleanID)
	delete(m.messages, cleanID)
	return nil
}

func (m *MemoryStore) AppendMessage(_ context.Context, sessionID string, msg Message) (Message, error) {
	cleanID := strings.TrimSpace(sessionID)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.sessions[cleanID]
	if !exists {
		return Message{}, ErrSessionNotFound
	}
	existingMsgs := m.messages[cleanID]
	nextMsgSeq := 1
	if len(existingMsgs) > 0 {
		nextMsgSeq = existingMsgs[len(existingMsgs)-1].Seq + 1
	}
	msg.SessionID = cleanID
	msg.Seq = nextMsgSeq
	if len(msg.ToolCalls) > 0 {
		msg.ToolCallsJSON = marshalToolCalls(msg.ToolCalls)
	}
	if msg.Meta != nil {
		msg.MetaJSON = marshalMessageMeta(msg.Meta)
	}
	stored := cloneMessage(msg)
	m.messages[cleanID] = append(existingMsgs, stored)
	if msg.CreatedAt != "" {
		entry.Session.UpdatedAt = msg.CreatedAt
		m.nextSeq++
		entry.Order = m.nextSeq
	}
	return cloneMessage(stored), nil
}

func (m *MemoryStore) ListMessages(_ context.Context, sessionID string) ([]Message, error) {
	cleanID := strings.TrimSpace(sessionID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	msgs := m.messages[cleanID]
	out := make([]Message, 0, len(msgs))
	for _, msg := range msgs {
		out = append(out, cloneMessage(msg))
	}
	return out, nil
}

func (m *MemoryStore) ReplaceMessages(_ context.Context, sessionID string, messages []Message, updatedAt string) error {
	cleanID := strings.TrimSpace(sessionID)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.sessions[cleanID]
	if !exists {
		return ErrSessionNotFound
	}
	replaced := make([]Message, 0, len(messages))
	for idx, msg := range messages {
		copied := cloneMessage(msg)
		copied.SessionID = cleanID
		copied.Seq = idx + 1
		if len(copied.ToolCalls) > 0 {
			copied.ToolCallsJSON = marshalToolCalls(copied.ToolCalls)
		}
		if copied.Meta != nil {
			copied.MetaJSON = marshalMessageMeta(copied.Meta)
		}
		replaced = append(replaced, copied)
	}
	m.messages[cleanID] = replaced
	if updatedAt != "" {
		entry.Session.UpdatedAt = updatedAt
		m.nextSeq++
		entry.Order = m.nextSeq
	}
	return nil
}

func (m *MemoryStore) AddTelemetry(_ context.Context, sessionID string, tokensIn, tokensOut, rtkSaved int64, updatedAt string) error {
	cleanID := strings.TrimSpace(sessionID)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.sessions[cleanID]
	if !exists {
		return ErrSessionNotFound
	}
	entry.Session.TotalTokensIn += tokensIn
	entry.Session.TotalTokensOut += tokensOut
	entry.Session.RTKTokensSaved += rtkSaved
	if updatedAt != "" {
		entry.Session.UpdatedAt = updatedAt
		m.nextSeq++
		entry.Order = m.nextSeq
	}
	return nil
}

func (m *MemoryStore) SetStatus(_ context.Context, sessionID, status, updatedAt string) error {
	cleanID := strings.TrimSpace(sessionID)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.sessions[cleanID]
	if !exists {
		return ErrSessionNotFound
	}
	entry.Session.Status = status
	if updatedAt != "" {
		entry.Session.UpdatedAt = updatedAt
		m.nextSeq++
		entry.Order = m.nextSeq
	}
	return nil
}

func cloneMessage(msg Message) Message {
	copied := msg
	if len(msg.ToolCalls) > 0 {
		copied.ToolCalls = make([]ToolCall, len(msg.ToolCalls))
		copy(copied.ToolCalls, msg.ToolCalls)
	}
	if msg.Meta != nil {
		metaCopy := *msg.Meta
		copied.Meta = &metaCopy
	}
	return copied
}

// JSONFileStore wraps MemoryStore with atomic JSON snapshot persistence on disk.
type JSONFileStore struct {
	mem      *MemoryStore
	filePath string
	fileMu   sync.Mutex
}

type jsonStoreSnapshot struct {
	Sessions []Session            `json:"sessions"`
	Messages map[string][]Message `json:"messages"`
}

// NewJSONFileStore loads an existing session snapshot from filePath (if present) and persists mutations atomically.
func NewJSONFileStore(filePath string) (*JSONFileStore, error) {
	cleaned := strings.TrimSpace(filePath)
	if cleaned == "" {
		return nil, errors.New("session store file path is required")
	}
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve session store path: %w", err)
	}
	fs := &JSONFileStore{
		mem:      NewMemoryStore(),
		filePath: absPath,
	}
	if err := fs.load(); err != nil {
		return nil, err
	}
	return fs, nil
}

func (f *JSONFileStore) load() error {
	raw, err := os.ReadFile(f.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read session store %s: %w", f.filePath, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var snap jsonStoreSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("decode session store %s: %w", f.filePath, err)
	}
	for _, sess := range snap.Sessions {
		_ = f.mem.InsertSession(context.Background(), sess)
		if msgs := snap.Messages[sess.ID]; len(msgs) > 0 {
			_ = f.mem.ReplaceMessages(context.Background(), sess.ID, msgs, sess.UpdatedAt)
		}
	}
	return nil
}

func (f *JSONFileStore) flush() error {
	f.fileMu.Lock()
	defer f.fileMu.Unlock()

	sessions, err := f.mem.ListSessions(context.Background(), 500)
	if err != nil {
		return err
	}
	msgMap := make(map[string][]Message, len(sessions))
	for _, sess := range sessions {
		msgs, msgErr := f.mem.ListMessages(context.Background(), sess.ID)
		if msgErr != nil {
			return msgErr
		}
		msgMap[sess.ID] = msgs
	}
	encoded, err := json.MarshalIndent(jsonStoreSnapshot{
		Sessions: sessions,
		Messages: msgMap,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(f.filePath), 0o755); err != nil {
		return fmt.Errorf("create session store dir: %w", err)
	}
	tmpPath := f.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write temp session store: %w", err)
	}
	if err := os.Rename(tmpPath, f.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace session store: %w", err)
	}
	return nil
}

func (f *JSONFileStore) InsertSession(ctx context.Context, session Session) error {
	if err := f.mem.InsertSession(ctx, session); err != nil {
		return err
	}
	return f.flush()
}

func (f *JSONFileStore) ListSessions(ctx context.Context, limit int) ([]Session, error) {
	return f.mem.ListSessions(ctx, limit)
}

func (f *JSONFileStore) GetSession(ctx context.Context, sessionID string) (Session, error) {
	return f.mem.GetSession(ctx, sessionID)
}

func (f *JSONFileStore) UpdateSession(ctx context.Context, session Session) error {
	if err := f.mem.UpdateSession(ctx, session); err != nil {
		return err
	}
	return f.flush()
}

func (f *JSONFileStore) DeleteSession(ctx context.Context, sessionID string) error {
	if err := f.mem.DeleteSession(ctx, sessionID); err != nil {
		return err
	}
	return f.flush()
}

func (f *JSONFileStore) AppendMessage(ctx context.Context, sessionID string, msg Message) (Message, error) {
	saved, err := f.mem.AppendMessage(ctx, sessionID, msg)
	if err != nil {
		return Message{}, err
	}
	if flushErr := f.flush(); flushErr != nil {
		return Message{}, flushErr
	}
	return saved, nil
}

func (f *JSONFileStore) ListMessages(ctx context.Context, sessionID string) ([]Message, error) {
	return f.mem.ListMessages(ctx, sessionID)
}

func (f *JSONFileStore) ReplaceMessages(ctx context.Context, sessionID string, messages []Message, updatedAt string) error {
	if err := f.mem.ReplaceMessages(ctx, sessionID, messages, updatedAt); err != nil {
		return err
	}
	return f.flush()
}

func (f *JSONFileStore) AddTelemetry(ctx context.Context, sessionID string, tokensIn, tokensOut, rtkSaved int64, updatedAt string) error {
	if err := f.mem.AddTelemetry(ctx, sessionID, tokensIn, tokensOut, rtkSaved, updatedAt); err != nil {
		return err
	}
	return f.flush()
}

func (f *JSONFileStore) SetStatus(ctx context.Context, sessionID, status, updatedAt string) error {
	if err := f.mem.SetStatus(ctx, sessionID, status, updatedAt); err != nil {
		return err
	}
	return f.flush()
}
