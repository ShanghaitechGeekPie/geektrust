package session

// GatewaysForGroup restricts configured gateways to the assigned group. Missing
// groups may use the flattened list only when compatibility explicitly allows it.
func (c *Credential) GatewaysForGroup(group string) []string {
	var assigned []string
	if c.Policy != nil {
		if group == "" {
			assigned = c.Policy.Gateways
		} else {
			assigned = c.Policy.NodeGroups[group]
		}
	}
	if len(assigned) == 0 && (group == "" || c.MissingGatewayGroupFallback) {
		if c.Policy != nil {
			assigned = c.Policy.Gateways
		}
		if len(assigned) == 0 {
			assigned = c.Gateways
		}
	}
	if c.GatewayOverride {
		var matching []string
		for _, addr := range assigned {
			for _, allowed := range c.Gateways {
				if addr == allowed {
					matching = append(matching, addr)
					break
				}
			}
		}
		return matching
	}
	return append([]string(nil), assigned...)
}

func (c *Credential) GatewayGroupForApp(appID string) string {
	if c.Policy == nil {
		return ""
	}
	if group := c.Policy.AppNodeGroups[appID]; group != "" {
		return group
	}
	return c.Policy.MajorNodeGroup
}

func (c *Credential) GatewaysForApp(appID string) []string {
	return c.GatewaysForGroup(c.GatewayGroupForApp(appID))
}
