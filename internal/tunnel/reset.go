package tunnel

import "context"

func (m *Manager) Reset() {
	m.mu.Lock()
	if call := m.connecting; call != nil {
		m.connecting = nil
		call.cancel()
		if !call.finished {
			call.err = context.Canceled
			call.finished = true
			close(call.done)
		}
	}
	if m.cur != nil {
		m.cur.Close()
		m.cur = nil
	}
	m.mu.Unlock()
	m.groupsMu.Lock()
	for key, g := range m.groups {
		g.Close()
		delete(m.groups, key)
	}
	m.groupsMu.Unlock()
}
