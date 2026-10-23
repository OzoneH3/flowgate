package daemon

import "log"

// RepairMigratedEssential is called after initial discovery and before restoring
// protection. Persistence precedes publication, using the ordinary rule writer.
func (e *Engine) RepairMigratedEssential() error {
	if e.Essential == nil {
		return nil
	}
	snapshot := e.Essential.Snapshot()
	e.mu.Lock()
	defer e.mu.Unlock()
	next := append(e.rules[:0:0], e.rules...)
	var ids []string
	for i, r := range next {
		if repaired, ok := snapshot.RepairMigratedRule(r, e.Now()); ok {
			next[i] = repaired
			ids = append(ids, r.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	if err := e.publishRulesLocked(next); err != nil {
		return err
	}
	for _, id := range ids {
		log.Printf("essential preset %s: repaired revision-format migration metadata against identical current scope", id)
	}
	return nil
}
