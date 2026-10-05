package tunnel

func (m *Manager) Reset() {
	m.mu.Lock()
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
