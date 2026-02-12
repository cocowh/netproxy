package subscription

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ClashConfig represents a Clash configuration file.
type ClashConfig struct {
	Port               int                      `yaml:"port,omitempty"`
	SocksPort          int                      `yaml:"socks-port,omitempty"`
	AllowLAN           bool                     `yaml:"allow-lan,omitempty"`
	Mode               string                   `yaml:"mode,omitempty"`
	LogLevel           string                   `yaml:"log-level,omitempty"`
	ExternalController string                   `yaml:"external-controller,omitempty"`
	DNS                *ClashDNS                `yaml:"dns,omitempty"`
	Proxies            []map[string]interface{} `yaml:"proxies,omitempty"`
	ProxyGroups        []ClashProxyGroup        `yaml:"proxy-groups,omitempty"`
	Rules              []string                 `yaml:"rules,omitempty"`
}

// ClashDNS represents Clash DNS configuration.
type ClashDNS struct {
	Enable       bool     `yaml:"enable"`
	IPv6         bool     `yaml:"ipv6"`
	Listen       string   `yaml:"listen,omitempty"`
	EnhancedMode string   `yaml:"enhanced-mode,omitempty"`
	FakeIPRange  string   `yaml:"fake-ip-range,omitempty"`
	Nameserver   []string `yaml:"nameserver,omitempty"`
	Fallback     []string `yaml:"fallback,omitempty"`
}

// ClashProxyGroup represents a Clash proxy group.
type ClashProxyGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies,omitempty"`
	URL      string   `yaml:"url,omitempty"`
	Interval int      `yaml:"interval,omitempty"`
}

// ClashGenerator generates Clash configuration.
type ClashGenerator struct {
	config *ClashConfig
}

// NewClashGenerator creates a new Clash configuration generator.
func NewClashGenerator() *ClashGenerator {
	return &ClashGenerator{
		config: &ClashConfig{
			Port:               7890,
			SocksPort:          7891,
			AllowLAN:           false,
			Mode:               "rule",
			LogLevel:           "info",
			ExternalController: "127.0.0.1:9090",
			DNS: &ClashDNS{
				Enable:       true,
				IPv6:         false,
				EnhancedMode: "fake-ip",
				FakeIPRange:  "198.18.0.1/16",
				Nameserver: []string{
					"114.114.114.114",
					"8.8.8.8",
				},
			},
			Proxies:     []map[string]interface{}{},
			ProxyGroups: []ClashProxyGroup{},
			Rules: []string{
				"GEOIP,CN,DIRECT",
				"MATCH,Proxy",
			},
		},
	}
}

// SetPort sets the HTTP proxy port.
func (g *ClashGenerator) SetPort(port int) *ClashGenerator {
	g.config.Port = port
	return g
}

// SetSocksPort sets the SOCKS5 proxy port.
func (g *ClashGenerator) SetSocksPort(port int) *ClashGenerator {
	g.config.SocksPort = port
	return g
}

// SetAllowLAN sets whether to allow LAN connections.
func (g *ClashGenerator) SetAllowLAN(allow bool) *ClashGenerator {
	g.config.AllowLAN = allow
	return g
}

// SetMode sets the proxy mode (rule, global, direct).
func (g *ClashGenerator) SetMode(mode string) *ClashGenerator {
	g.config.Mode = mode
	return g
}

// AddNode adds a proxy node.
func (g *ClashGenerator) AddNode(node *Node) *ClashGenerator {
	g.config.Proxies = append(g.config.Proxies, node.ClashConfig())
	return g
}

// AddNodes adds multiple proxy nodes.
func (g *ClashGenerator) AddNodes(nodes []*Node) *ClashGenerator {
	for _, node := range nodes {
		g.AddNode(node)
	}
	return g
}

// AddProxyGroup adds a proxy group.
func (g *ClashGenerator) AddProxyGroup(group ClashProxyGroup) *ClashGenerator {
	g.config.ProxyGroups = append(g.config.ProxyGroups, group)
	return g
}

// SetRules sets the routing rules.
func (g *ClashGenerator) SetRules(rules []string) *ClashGenerator {
	g.config.Rules = rules
	return g
}

// AddRule adds a routing rule.
func (g *ClashGenerator) AddRule(rule string) *ClashGenerator {
	// Insert before MATCH rule
	if len(g.config.Rules) > 0 {
		lastIdx := len(g.config.Rules) - 1
		if g.config.Rules[lastIdx][:5] == "MATCH" {
			g.config.Rules = append(g.config.Rules[:lastIdx], rule, g.config.Rules[lastIdx])
			return g
		}
	}
	g.config.Rules = append(g.config.Rules, rule)
	return g
}

// GenerateDefaultGroups generates default proxy groups based on added nodes.
func (g *ClashGenerator) GenerateDefaultGroups() *ClashGenerator {
	if len(g.config.Proxies) == 0 {
		return g
	}

	// Collect proxy names
	var proxyNames []string
	for _, proxy := range g.config.Proxies {
		if name, ok := proxy["name"].(string); ok {
			proxyNames = append(proxyNames, name)
		}
	}

	// Add DIRECT and REJECT
	allProxies := append([]string{"DIRECT", "REJECT"}, proxyNames...)

	// Create default groups
	g.config.ProxyGroups = []ClashProxyGroup{
		{
			Name:    "Proxy",
			Type:    "select",
			Proxies: append([]string{"auto"}, proxyNames...),
		},
		{
			Name:     "auto",
			Type:     "url-test",
			Proxies:  proxyNames,
			URL:      "http://www.gstatic.com/generate_204",
			Interval: 300,
		},
		{
			Name:    "Fallback",
			Type:    "select",
			Proxies: allProxies,
		},
	}

	return g
}

// Generate generates the Clash configuration as YAML.
func (g *ClashGenerator) Generate() ([]byte, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

	if err := encoder.Encode(g.config); err != nil {
		return nil, fmt.Errorf("failed to encode Clash config: %w", err)
	}

	return buf.Bytes(), nil
}

// GenerateString generates the Clash configuration as a string.
func (g *ClashGenerator) GenerateString() (string, error) {
	data, err := g.Generate()
	if err != nil {
		return "", err
	}
	return string(data), nil
}
