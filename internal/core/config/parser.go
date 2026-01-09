package config

import (
	"fmt"
	"strings"

	"github.com/cocowh/netproxy/internal/feature/acl"
	"github.com/cocowh/netproxy/internal/feature/router"
)

// ParseRule parses a rule string into an action and a definition
func ParseRule(ruleStr string) (acl.Action, string, error) {
	// Expected format: "action: matcher" e.g. "proxy: domain:google.com"

	var action acl.Action
	var ruleDef string

	if len(ruleStr) > 6 && ruleStr[:6] == "proxy:" {
		action = acl.Proxy
		ruleDef = ruleStr[6:]
	} else if len(ruleStr) > 6 && ruleStr[:6] == "block:" {
		action = acl.Block
		ruleDef = ruleStr[6:]
	} else if len(ruleStr) > 7 && ruleStr[:7] == "direct:" {
		action = acl.Direct
		ruleDef = ruleStr[7:]
	} else {
		return 0, "", fmt.Errorf("unknown action in rule: %s", ruleStr)
	}

	return action, strings.TrimSpace(ruleDef), nil
}

// LoadRules parses and adds rules to the router
func LoadRules(r router.Router, rules []string) error {
	for _, ruleStr := range rules {
		action, ruleDef, err := ParseRule(ruleStr)
		if err != nil {
			// Return error or log? For now, we return error and let caller decide
			// But to be robust, we might want to collect errors.
			// However, interface says return error.
			return fmt.Errorf("invalid rule '%s': %w", ruleStr, err)
		}

		if err := r.AddRule(ruleDef, action); err != nil {
			return fmt.Errorf("failed to add rule '%s': %w", ruleStr, err)
		}
	}
	return nil
}
