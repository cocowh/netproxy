package subscription

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNode(t *testing.T) {
	t.Run("SS_ClashConfig", func(t *testing.T) {
		node := &Node{
			Name:     "SS Node",
			Type:     NodeTypeSS,
			Server:   "example.com",
			Port:     8388,
			Password: "testpassword",
			Cipher:   "aes-256-gcm",
		}

		config := node.ClashConfig()

		if config["name"] != "SS Node" {
			t.Errorf("Expected name 'SS Node', got '%s'", config["name"])
		}
		if config["type"] != "ss" {
			t.Errorf("Expected type 'ss', got '%s'", config["type"])
		}
		if config["server"] != "example.com" {
			t.Errorf("Expected server 'example.com', got '%s'", config["server"])
		}
		if config["port"] != 8388 {
			t.Errorf("Expected port 8388, got %v", config["port"])
		}
		if config["cipher"] != "aes-256-gcm" {
			t.Errorf("Expected cipher 'aes-256-gcm', got '%s'", config["cipher"])
		}
		if config["password"] != "testpassword" {
			t.Errorf("Expected password 'testpassword', got '%s'", config["password"])
		}
	})

	t.Run("VMess_ClashConfig", func(t *testing.T) {
		node := &Node{
			Name:    "VMess Node",
			Type:    NodeTypeVMess,
			Server:  "vmess.example.com",
			Port:    443,
			UUID:    "12345678-1234-1234-1234-123456789012",
			Cipher:  "auto",
			Network: "ws",
			TLS:     true,
			SNI:     "vmess.example.com",
			Path:    "/ws",
		}

		config := node.ClashConfig()

		if config["type"] != "vmess" {
			t.Errorf("Expected type 'vmess', got '%s'", config["type"])
		}
		if config["uuid"] != node.UUID {
			t.Errorf("Expected uuid '%s', got '%s'", node.UUID, config["uuid"])
		}
		if config["alterId"] != 0 {
			t.Errorf("Expected alterId 0, got %v", config["alterId"])
		}
		if config["tls"] != true {
			t.Errorf("Expected tls true, got %v", config["tls"])
		}
		if config["network"] != "ws" {
			t.Errorf("Expected network 'ws', got '%s'", config["network"])
		}
	})

	t.Run("Trojan_ClashConfig", func(t *testing.T) {
		node := &Node{
			Name:     "Trojan Node",
			Type:     NodeTypeTrojan,
			Server:   "trojan.example.com",
			Port:     443,
			Password: "trojanpassword",
			SNI:      "trojan.example.com",
		}

		config := node.ClashConfig()

		if config["type"] != "trojan" {
			t.Errorf("Expected type 'trojan', got '%s'", config["type"])
		}
		if config["password"] != "trojanpassword" {
			t.Errorf("Expected password 'trojanpassword', got '%s'", config["password"])
		}
		if config["sni"] != "trojan.example.com" {
			t.Errorf("Expected sni 'trojan.example.com', got '%s'", config["sni"])
		}
	})

	t.Run("SS_V2RayLink", func(t *testing.T) {
		node := &Node{
			Name:     "SS Test",
			Type:     NodeTypeSS,
			Server:   "ss.example.com",
			Port:     8388,
			Password: "testpassword",
			Cipher:   "aes-256-gcm",
		}

		link := node.V2RayLink()

		if !strings.HasPrefix(link, "ss://") {
			t.Errorf("SS link should start with 'ss://', got '%s'", link)
		}
	})

	t.Run("VMess_V2RayLink", func(t *testing.T) {
		node := &Node{
			Name:    "VMess Test",
			Type:    NodeTypeVMess,
			Server:  "vmess.example.com",
			Port:    443,
			UUID:    "12345678-1234-1234-1234-123456789012",
			Network: "tcp",
		}

		link := node.V2RayLink()

		if !strings.HasPrefix(link, "vmess://") {
			t.Errorf("VMess link should start with 'vmess://', got '%s'", link)
		}
	})

	t.Run("VLESS_V2RayLink", func(t *testing.T) {
		node := &Node{
			Name:    "VLESS Test",
			Type:    NodeTypeVLESS,
			Server:  "vless.example.com",
			Port:    443,
			UUID:    "12345678-1234-1234-1234-123456789012",
			Network: "tcp",
			TLS:     true,
		}

		link := node.V2RayLink()

		if !strings.HasPrefix(link, "vless://") {
			t.Errorf("VLESS link should start with 'vless://', got '%s'", link)
		}

		if !strings.Contains(link, node.UUID) {
			t.Errorf("VLESS link should contain UUID")
		}

		if !strings.Contains(link, "security=tls") {
			t.Errorf("VLESS link should contain security=tls")
		}
	})

	t.Run("Trojan_V2RayLink", func(t *testing.T) {
		node := &Node{
			Name:     "Trojan Test",
			Type:     NodeTypeTrojan,
			Server:   "trojan.example.com",
			Port:     443,
			Password: "trojanpassword",
		}

		link := node.V2RayLink()

		if !strings.HasPrefix(link, "trojan://") {
			t.Errorf("Trojan link should start with 'trojan://', got '%s'", link)
		}

		if !strings.Contains(link, "trojanpassword") {
			t.Errorf("Trojan link should contain password")
		}
	})

	t.Run("SS_SurgeConfig", func(t *testing.T) {
		node := &Node{
			Name:     "SS Surge",
			Type:     NodeTypeSS,
			Server:   "ss.example.com",
			Port:     8388,
			Password: "testpassword",
			Cipher:   "aes-256-gcm",
		}

		config := node.SurgeConfig()

		if !strings.HasPrefix(config, "SS Surge = ss") {
			t.Errorf("Surge config should start with name and type, got '%s'", config)
		}

		if !strings.Contains(config, "ss.example.com") {
			t.Errorf("Surge config should contain server")
		}

		if !strings.Contains(config, "8388") {
			t.Errorf("Surge config should contain port")
		}

		if !strings.Contains(config, "encrypt-method=aes-256-gcm") {
			t.Errorf("Surge config should contain cipher")
		}
	})
}

func TestClashGenerator(t *testing.T) {
	nodes := []*Node{
		{
			Name:     "SS Node",
			Type:     NodeTypeSS,
			Server:   "ss.example.com",
			Port:     8388,
			Password: "password1",
			Cipher:   "aes-256-gcm",
		},
		{
			Name:    "VMess Node",
			Type:    NodeTypeVMess,
			Server:  "vmess.example.com",
			Port:    443,
			UUID:    "12345678-1234-1234-1234-123456789012",
			Network: "ws",
			TLS:     true,
		},
	}

	gen := NewClashGenerator()
	gen.AddNodes(nodes)
	gen.GenerateDefaultGroups()
	config, err := gen.GenerateString()
	if err != nil {
		t.Fatalf("Failed to generate config: %v", err)
	}

	if !strings.Contains(config, "proxies:") {
		t.Error("Config should contain 'proxies:'")
	}

	if !strings.Contains(config, "SS Node") {
		t.Error("Config should contain SS Node")
	}

	if !strings.Contains(config, "VMess Node") {
		t.Error("Config should contain VMess Node")
	}

	if !strings.Contains(config, "proxy-groups:") {
		t.Error("Config should contain 'proxy-groups:'")
	}
}

func TestV2RayGenerator(t *testing.T) {
	nodes := []*Node{
		{
			Name:     "SS Node",
			Type:     NodeTypeSS,
			Server:   "ss.example.com",
			Port:     8388,
			Password: "password1",
			Cipher:   "aes-256-gcm",
		},
		{
			Name:   "VMess Node",
			Type:   NodeTypeVMess,
			Server: "vmess.example.com",
			Port:   443,
			UUID:   "12345678-1234-1234-1234-123456789012",
		},
	}

	gen := NewV2RayGenerator()
	gen.AddNodes(nodes)
	output := gen.Generate()

	// Output should be base64 encoded
	decoded, err := base64.StdEncoding.DecodeString(output)
	if err != nil {
		t.Fatalf("Output should be base64 encoded: %v", err)
	}

	lines := strings.Split(string(decoded), "\n")
	if len(lines) < 2 {
		t.Errorf("Expected at least 2 lines, got %d", len(lines))
	}

	// First line should be SS link
	if !strings.HasPrefix(lines[0], "ss://") {
		t.Errorf("First line should be SS link, got '%s'", lines[0])
	}

	// Second line should be VMess link
	if !strings.HasPrefix(lines[1], "vmess://") {
		t.Errorf("Second line should be VMess link, got '%s'", lines[1])
	}
}

func TestSurgeGenerator(t *testing.T) {
	nodes := []*Node{
		{
			Name:     "SS Node",
			Type:     NodeTypeSS,
			Server:   "ss.example.com",
			Port:     8388,
			Password: "password1",
			Cipher:   "aes-256-gcm",
		},
		{
			Name:     "Trojan Node",
			Type:     NodeTypeTrojan,
			Server:   "trojan.example.com",
			Port:     443,
			Password: "trojanpassword",
		},
	}

	gen := NewSurgeGenerator()
	gen.AddNodes(nodes)
	config, err := gen.GenerateString()
	if err != nil {
		t.Fatalf("Failed to generate config: %v", err)
	}

	if !strings.Contains(config, "[Proxy]") {
		t.Error("Config should contain '[Proxy]' section")
	}

	if !strings.Contains(config, "[Proxy Group]") {
		t.Error("Config should contain '[Proxy Group]' section")
	}

	if !strings.Contains(config, "SS Node") {
		t.Error("Config should contain SS Node")
	}

	if !strings.Contains(config, "Trojan Node") {
		t.Error("Config should contain Trojan Node")
	}
}

func TestNodeTypes(t *testing.T) {
	types := []NodeType{
		NodeTypeSS,
		NodeTypeVMess,
		NodeTypeVLESS,
		NodeTypeTrojan,
		NodeTypeHTTP,
		NodeTypeSOCKS5,
	}

	for _, nt := range types {
		node := &Node{
			Name:     "Test",
			Type:     nt,
			Server:   "test.com",
			Port:     1234,
			Password: "test",
			UUID:     "12345678-1234-1234-1234-123456789012",
		}

		// Should not panic
		_ = node.ClashConfig()
		_ = node.V2RayLink()
		_ = node.SurgeConfig()
	}
}
