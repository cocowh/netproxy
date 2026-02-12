// Package subscription provides subscription link generation for various proxy clients.
package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// NodeType represents the type of proxy node.
type NodeType string

const (
	NodeTypeSS      NodeType = "ss"
	NodeTypeSSR     NodeType = "ssr"
	NodeTypeVMess   NodeType = "vmess"
	NodeTypeVLESS   NodeType = "vless"
	NodeTypeTrojan  NodeType = "trojan"
	NodeTypeHTTP    NodeType = "http"
	NodeTypeSOCKS5  NodeType = "socks5"
)

// Node represents a proxy node configuration.
type Node struct {
	Name     string            `json:"name"`
	Type     NodeType          `json:"type"`
	Server   string            `json:"server"`
	Port     int               `json:"port"`
	Password string            `json:"password,omitempty"`
	UUID     string            `json:"uuid,omitempty"`
	Cipher   string            `json:"cipher,omitempty"`
	Network  string            `json:"network,omitempty"` // tcp, ws, grpc, etc.
	TLS      bool              `json:"tls,omitempty"`
	SNI      string            `json:"sni,omitempty"`
	Path     string            `json:"path,omitempty"`
	Host     string            `json:"host,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// ClashConfig generates Clash configuration for the node.
func (n *Node) ClashConfig() map[string]interface{} {
	config := map[string]interface{}{
		"name":   n.Name,
		"type":   string(n.Type),
		"server": n.Server,
		"port":   n.Port,
	}

	switch n.Type {
	case NodeTypeSS:
		config["cipher"] = n.Cipher
		config["password"] = n.Password
	case NodeTypeVMess:
		config["uuid"] = n.UUID
		config["alterId"] = 0
		config["cipher"] = "auto"
		if n.Network != "" {
			config["network"] = n.Network
		}
		if n.TLS {
			config["tls"] = true
			if n.SNI != "" {
				config["servername"] = n.SNI
			}
		}
		if n.Network == "ws" {
			wsOpts := map[string]interface{}{}
			if n.Path != "" {
				wsOpts["path"] = n.Path
			}
			if n.Host != "" {
				wsOpts["headers"] = map[string]string{"Host": n.Host}
			}
			config["ws-opts"] = wsOpts
		}
	case NodeTypeVLESS:
		config["uuid"] = n.UUID
		config["flow"] = ""
		if n.Network != "" {
			config["network"] = n.Network
		}
		if n.TLS {
			config["tls"] = true
			if n.SNI != "" {
				config["servername"] = n.SNI
			}
		}
	case NodeTypeTrojan:
		config["password"] = n.Password
		if n.SNI != "" {
			config["sni"] = n.SNI
		}
	case NodeTypeSOCKS5:
		if n.Password != "" {
			// Parse username:password
			parts := strings.SplitN(n.Password, ":", 2)
			if len(parts) == 2 {
				config["username"] = parts[0]
				config["password"] = parts[1]
			}
		}
	case NodeTypeHTTP:
		if n.Password != "" {
			parts := strings.SplitN(n.Password, ":", 2)
			if len(parts) == 2 {
				config["username"] = parts[0]
				config["password"] = parts[1]
			}
		}
		if n.TLS {
			config["tls"] = true
		}
	}

	return config
}

// V2RayLink generates V2Ray share link for the node.
func (n *Node) V2RayLink() string {
	switch n.Type {
	case NodeTypeSS:
		return n.ssLink()
	case NodeTypeVMess:
		return n.vmessLink()
	case NodeTypeVLESS:
		return n.vlessLink()
	case NodeTypeTrojan:
		return n.trojanLink()
	default:
		return ""
	}
}

func (n *Node) ssLink() string {
	// ss://method:password@server:port#name
	userInfo := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", n.Cipher, n.Password)))
	return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, n.Server, n.Port, url.QueryEscape(n.Name))
}

func (n *Node) vmessLink() string {
	// vmess://base64(json)
	config := map[string]interface{}{
		"v":    "2",
		"ps":   n.Name,
		"add":  n.Server,
		"port": n.Port,
		"id":   n.UUID,
		"aid":  0,
		"net":  n.Network,
		"type": "none",
		"host": n.Host,
		"path": n.Path,
		"tls":  "",
	}
	if n.TLS {
		config["tls"] = "tls"
	}
	if n.Network == "" {
		config["net"] = "tcp"
	}

	jsonBytes, _ := json.Marshal(config)
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonBytes)
}

func (n *Node) vlessLink() string {
	// vless://uuid@server:port?params#name
	params := url.Values{}
	if n.Network != "" {
		params.Set("type", n.Network)
	} else {
		params.Set("type", "tcp")
	}
	params.Set("encryption", "none")
	if n.TLS {
		params.Set("security", "tls")
		if n.SNI != "" {
			params.Set("sni", n.SNI)
		}
	}
	if n.Path != "" {
		params.Set("path", n.Path)
	}
	if n.Host != "" {
		params.Set("host", n.Host)
	}

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", n.UUID, n.Server, n.Port, params.Encode(), url.QueryEscape(n.Name))
}

func (n *Node) trojanLink() string {
	// trojan://password@server:port?params#name
	params := url.Values{}
	if n.SNI != "" {
		params.Set("sni", n.SNI)
	}
	if n.Network != "" && n.Network != "tcp" {
		params.Set("type", n.Network)
		if n.Path != "" {
			params.Set("path", n.Path)
		}
		if n.Host != "" {
			params.Set("host", n.Host)
		}
	}

	link := fmt.Sprintf("trojan://%s@%s:%d", url.QueryEscape(n.Password), n.Server, n.Port)
	if len(params) > 0 {
		link += "?" + params.Encode()
	}
	link += "#" + url.QueryEscape(n.Name)
	return link
}

// SurgeConfig generates Surge proxy configuration line.
func (n *Node) SurgeConfig() string {
	switch n.Type {
	case NodeTypeSS:
		return fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s",
			n.Name, n.Server, n.Port, n.Cipher, n.Password)
	case NodeTypeTrojan:
		config := fmt.Sprintf("%s = trojan, %s, %d, password=%s",
			n.Name, n.Server, n.Port, n.Password)
		if n.SNI != "" {
			config += fmt.Sprintf(", sni=%s", n.SNI)
		}
		return config
	case NodeTypeHTTP:
		config := fmt.Sprintf("%s = http, %s, %d", n.Name, n.Server, n.Port)
		if n.Password != "" {
			parts := strings.SplitN(n.Password, ":", 2)
			if len(parts) == 2 {
				config += fmt.Sprintf(", username=%s, password=%s", parts[0], parts[1])
			}
		}
		if n.TLS {
			config += ", tls=true"
		}
		return config
	case NodeTypeSOCKS5:
		config := fmt.Sprintf("%s = socks5, %s, %d", n.Name, n.Server, n.Port)
		if n.Password != "" {
			parts := strings.SplitN(n.Password, ":", 2)
			if len(parts) == 2 {
				config += fmt.Sprintf(", username=%s, password=%s", parts[0], parts[1])
			}
		}
		if n.TLS {
			config += ", tls=true"
		}
		return config
	default:
		return ""
	}
}
