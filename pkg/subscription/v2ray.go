package subscription

import (
	"encoding/base64"
	"strings"
)

// V2RayGenerator generates V2Ray subscription links.
type V2RayGenerator struct {
	nodes []*Node
}

// NewV2RayGenerator creates a new V2Ray subscription generator.
func NewV2RayGenerator() *V2RayGenerator {
	return &V2RayGenerator{
		nodes: []*Node{},
	}
}

// AddNode adds a proxy node.
func (g *V2RayGenerator) AddNode(node *Node) *V2RayGenerator {
	g.nodes = append(g.nodes, node)
	return g
}

// AddNodes adds multiple proxy nodes.
func (g *V2RayGenerator) AddNodes(nodes []*Node) *V2RayGenerator {
	g.nodes = append(g.nodes, nodes...)
	return g
}

// Generate generates the V2Ray subscription content (base64 encoded links).
func (g *V2RayGenerator) Generate() string {
	var links []string
	for _, node := range g.nodes {
		link := node.V2RayLink()
		if link != "" {
			links = append(links, link)
		}
	}

	content := strings.Join(links, "\n")
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// GenerateRaw generates the V2Ray subscription content without base64 encoding.
func (g *V2RayGenerator) GenerateRaw() string {
	var links []string
	for _, node := range g.nodes {
		link := node.V2RayLink()
		if link != "" {
			links = append(links, link)
		}
	}
	return strings.Join(links, "\n")
}

// GenerateLinks returns individual V2Ray links.
func (g *V2RayGenerator) GenerateLinks() []string {
	var links []string
	for _, node := range g.nodes {
		link := node.V2RayLink()
		if link != "" {
			links = append(links, link)
		}
	}
	return links
}
