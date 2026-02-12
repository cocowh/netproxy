// Package geosite implements domain matching based on GeoSite rules.
// GeoSite is a domain list format used by V2Ray/Xray for domain-based routing.
package geosite

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

// MatchType represents the type of domain matching
type MatchType int

const (
	// MatchTypePlain matches the domain exactly
	MatchTypePlain MatchType = iota
	// MatchTypeRegex matches using regular expression
	MatchTypeRegex
	// MatchTypeDomain matches the domain and all its subdomains
	MatchTypeDomain
	// MatchTypeFull matches the full domain exactly
	MatchTypeFull
)

// Rule represents a single domain rule
type Rule struct {
	Type   MatchType
	Value  string
	Attrs  map[string]string // Optional attributes like @cn, @ads
}

// Category represents a category of domains (e.g., "google", "cn")
type Category struct {
	Name  string
	Rules []*Rule
}

// GeoSite manages domain categories and matching
type GeoSite struct {
	categories map[string]*Category
	mu         sync.RWMutex
}

// New creates a new GeoSite instance
func New() *GeoSite {
	return &GeoSite{
		categories: make(map[string]*Category),
	}
}

// LoadFromFile loads GeoSite data from a text file
// Format: category:type:value[@attr1,attr2]
// Example:
//   google:domain:google.com
//   cn:full:baidu.com@cn
func (g *GeoSite) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return g.LoadFromReader(file)
}

// LoadFromReader loads GeoSite data from a reader
func (g *GeoSite) LoadFromReader(r io.Reader) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, categoryName, err := parseLine(line)
		if err != nil {
			continue // Skip invalid lines
		}

		category, ok := g.categories[categoryName]
		if !ok {
			category = &Category{
				Name:  categoryName,
				Rules: make([]*Rule, 0),
			}
			g.categories[categoryName] = category
		}

		category.Rules = append(category.Rules, rule)
	}

	return scanner.Err()
}

// parseLine parses a single line of GeoSite data
func parseLine(line string) (*Rule, string, error) {
	// Format: category:type:value[@attr1,attr2]
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 2 {
		return nil, "", errors.New("invalid format")
	}

	categoryName := strings.ToLower(parts[0])
	
	var matchType MatchType
	var value string

	if len(parts) == 2 {
		// Simple format: category:domain
		matchType = MatchTypeDomain
		value = parts[1]
	} else {
		// Full format: category:type:value
		switch strings.ToLower(parts[1]) {
		case "domain":
			matchType = MatchTypeDomain
		case "full":
			matchType = MatchTypeFull
		case "plain", "keyword":
			matchType = MatchTypePlain
		case "regex", "regexp":
			matchType = MatchTypeRegex
		default:
			return nil, "", errors.New("unknown match type")
		}
		value = parts[2]
	}

	// Parse attributes
	attrs := make(map[string]string)
	if idx := strings.Index(value, "@"); idx != -1 {
		attrStr := value[idx+1:]
		value = value[:idx]
		for _, attr := range strings.Split(attrStr, ",") {
			attr = strings.TrimSpace(attr)
			if attr != "" {
				attrs[attr] = ""
			}
		}
	}

	rule := &Rule{
		Type:  matchType,
		Value: strings.ToLower(value),
		Attrs: attrs,
	}

	return rule, categoryName, nil
}

// AddCategory adds a category with rules
func (g *GeoSite) AddCategory(name string, rules []*Rule) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.categories[strings.ToLower(name)] = &Category{
		Name:  name,
		Rules: rules,
	}
}

// GetCategory returns a category by name
func (g *GeoSite) GetCategory(name string) (*Category, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	cat, ok := g.categories[strings.ToLower(name)]
	return cat, ok
}

// Match checks if a domain matches any rule in the specified categories
func (g *GeoSite) Match(domain string, categories ...string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	domain = strings.ToLower(domain)

	for _, catName := range categories {
		cat, ok := g.categories[strings.ToLower(catName)]
		if !ok {
			continue
		}

		for _, rule := range cat.Rules {
			if matchRule(domain, rule) {
				return true
			}
		}
	}

	return false
}

// MatchWithAttr checks if a domain matches with specific attributes
func (g *GeoSite) MatchWithAttr(domain string, attr string, categories ...string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	domain = strings.ToLower(domain)
	attr = strings.ToLower(attr)

	for _, catName := range categories {
		cat, ok := g.categories[strings.ToLower(catName)]
		if !ok {
			continue
		}

		for _, rule := range cat.Rules {
			if _, hasAttr := rule.Attrs[attr]; hasAttr {
				if matchRule(domain, rule) {
					return true
				}
			}
		}
	}

	return false
}

// matchRule checks if a domain matches a single rule
func matchRule(domain string, rule *Rule) bool {
	switch rule.Type {
	case MatchTypeFull:
		return domain == rule.Value

	case MatchTypeDomain:
		// Match domain and all subdomains
		if domain == rule.Value {
			return true
		}
		return strings.HasSuffix(domain, "."+rule.Value)

	case MatchTypePlain:
		// Keyword match
		return strings.Contains(domain, rule.Value)

	case MatchTypeRegex:
		// For simplicity, we don't implement regex here
		// In production, you would use regexp.Compile
		return false

	default:
		return false
	}
}

// Categories returns all category names
func (g *GeoSite) Categories() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	names := make([]string, 0, len(g.categories))
	for name := range g.categories {
		names = append(names, name)
	}
	return names
}

// RuleCount returns the total number of rules
func (g *GeoSite) RuleCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	count := 0
	for _, cat := range g.categories {
		count += len(cat.Rules)
	}
	return count
}

// Clear removes all categories
func (g *GeoSite) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.categories = make(map[string]*Category)
}
