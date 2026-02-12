package subscription

import (
	"bytes"
	"fmt"
	"strings"
)

// SurgeConfig represents a Surge configuration file.
type SurgeConfig struct {
	General     map[string]string
	Replica     map[string]string
	Proxies     []*Node
	ProxyGroups []SurgeProxyGroup
	Rules       []string
}

// SurgeProxyGroup represents a Surge proxy group.
type SurgeProxyGroup struct {
	Name    string
	Type    string // select, url-test, fallback, load-balance
	Proxies []string
	URL     string
	Interval int
}

// SurgeGenerator generates Surge configuration.
type SurgeGenerator struct {
	config *SurgeConfig
}

// NewSurgeGenerator creates a new Surge configuration generator.
func NewSurgeGenerator() *SurgeGenerator {
	return &SurgeGenerator{
		config: &SurgeConfig{
			General: map[string]string{
				"loglevel":                   "notify",
				"dns-server":                 "system, 8.8.8.8, 8.8.4.4",
				"skip-proxy":                 "127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local",
				"external-controller-access": "password@0.0.0.0:6170",
			},
			Replica: map[string]string{
				"hide-apple-request":  "true",
				"hide-crashlytics":    "true",
				"hide-udp":            "false",
				"keyword-filter-type": "none",
			},
			Proxies:     []*Node{},
			ProxyGroups: []SurgeProxyGroup{},
			Rules: []string{
				"GEOIP,CN,DIRECT",
				"FINAL,Proxy,dns-failed",
			},
		},
	}
}

// SetGeneral sets a general configuration option.
func (g *SurgeGenerator) SetGeneral(key, value string) *SurgeGenerator {
	g.config.General[key] = value
	return g
}

// AddNode adds a proxy node.
func (g *SurgeGenerator) AddNode(node *Node) *SurgeGenerator {
	g.config.Proxies = append(g.config.Proxies, node)
	return g
}

// AddNodes adds multiple proxy nodes.
func (g *SurgeGenerator) AddNodes(nodes []*Node) *SurgeGenerator {
	g.config.Proxies = append(g.config.Proxies, nodes...)
	return g
}

// AddProxyGroup adds a proxy group.
func (g *SurgeGenerator) AddProxyGroup(group SurgeProxyGroup) *SurgeGenerator {
	g.config.ProxyGroups = append(g.config.ProxyGroups, group)
	return g
}

// SetRules sets the routing rules.
func (g *SurgeGenerator) SetRules(rules []string) *SurgeGenerator {
	g.config.Rules = rules
	return g
}

// AddRule adds a routing rule.
func (g *SurgeGenerator) AddRule(rule string) *SurgeGenerator {
	// Insert before FINAL rule
	if len(g.config.Rules) > 0 {
		lastIdx := len(g.config.Rules) - 1
		if strings.HasPrefix(g.config.Rules[lastIdx], "FINAL") {
			g.config.Rules = append(g.config.Rules[:lastIdx], rule, g.config.Rules[lastIdx])
			return g
		}
	}
	g.config.Rules = append(g.config.Rules, rule)
	return g
}

// GenerateDefaultGroups generates default proxy groups based on added nodes.
func (g *SurgeGenerator) GenerateDefaultGroups() *SurgeGenerator {
	if len(g.config.Proxies) == 0 {
		return g
	}

	// Collect proxy names
	var proxyNames []string
	for _, proxy := range g.config.Proxies {
		proxyNames = append(proxyNames, proxy.Name)
	}

	// Create default groups
	g.config.ProxyGroups = []SurgeProxyGroup{
		{
			Name:    "Proxy",
			Type:    "select",
			Proxies: append([]string{"Auto", "DIRECT"}, proxyNames...),
		},
		{
			Name:     "Auto",
			Type:     "url-test",
			Proxies:  proxyNames,
			URL:      "http://www.gstatic.com/generate_204",
			Interval: 300,
		},
	}

	return g
}

// Generate generates the Surge configuration.
func (g *SurgeGenerator) Generate() ([]byte, error) {
	var buf bytes.Buffer

	// [General]
	buf.WriteString("[General]\n")
	for key, value := range g.config.General {
		buf.WriteString(fmt.Sprintf("%s = %s\n", key, value))
	}
	buf.WriteString("\n")

	// [Replica]
	buf.WriteString("[Replica]\n")
	for key, value := range g.config.Replica {
		buf.WriteString(fmt.Sprintf("%s = %s\n", key, value))
	}
	buf.WriteString("\n")

	// [Proxy]
	buf.WriteString("[Proxy]\n")
	buf.WriteString("DIRECT = direct\n")
	buf.WriteString("REJECT = reject\n")
	for _, proxy := range g.config.Proxies {
		line := proxy.SurgeConfig()
		if line != "" {
			buf.WriteString(line + "\n")
		}
	}
	buf.WriteString("\n")

	// [Proxy Group]
	buf.WriteString("[Proxy Group]\n")
	for _, group := range g.config.ProxyGroups {
		line := g.formatProxyGroup(group)
		buf.WriteString(line + "\n")
	}
	buf.WriteString("\n")

	// [Rule]
	buf.WriteString("[Rule]\n")
	for _, rule := range g.config.Rules {
		buf.WriteString(rule + "\n")
	}

	return buf.Bytes(), nil
}

// formatProxyGroup formats a proxy group for Surge configuration.
func (g *SurgeGenerator) formatProxyGroup(group SurgeProxyGroup) string {
	proxies := strings.Join(group.Proxies, ", ")

	switch group.Type {
	case "select":
		return fmt.Sprintf("%s = select, %s", group.Name, proxies)
	case "url-test":
		return fmt.Sprintf("%s = url-test, %s, url=%s, interval=%d",
			group.Name, proxies, group.URL, group.Interval)
	case "fallback":
		return fmt.Sprintf("%s = fallback, %s, url=%s, interval=%d",
			group.Name, proxies, group.URL, group.Interval)
	case "load-balance":
		return fmt.Sprintf("%s = load-balance, %s, url=%s, interval=%d",
			group.Name, proxies, group.URL, group.Interval)
	default:
		return fmt.Sprintf("%s = select, %s", group.Name, proxies)
	}
}

// GenerateString generates the Surge configuration as a string.
func (g *SurgeGenerator) GenerateString() (string, error) {
	data, err := g.Generate()
	if err != nil {
		return "", err
	}
	return string(data), nil
}
