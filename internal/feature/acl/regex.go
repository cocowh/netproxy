package acl

import (
	"context"
	"regexp"
	"strings"
	"sync"
)

// RegexMatcher matches strings against regular expressions
type RegexMatcher struct {
	mu       sync.RWMutex
	patterns []*compiledPattern
}

type compiledPattern struct {
	pattern string
	regex   *regexp.Regexp
	action  Action
}

// NewRegexMatcher creates a new regex matcher
func NewRegexMatcher() *RegexMatcher {
	return &RegexMatcher{
		patterns: make([]*compiledPattern, 0),
	}
}

// AddPattern adds a regex pattern with an action
func (m *RegexMatcher) AddPattern(pattern string, action Action) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.patterns = append(m.patterns, &compiledPattern{
		pattern: pattern,
		regex:   regex,
		action:  action,
	})

	return nil
}

// AddPatterns adds multiple patterns with the same action
func (m *RegexMatcher) AddPatterns(patterns []string, action Action) error {
	for _, pattern := range patterns {
		if err := m.AddPattern(pattern, action); err != nil {
			return err
		}
	}
	return nil
}

// Match checks if a string matches any pattern and returns the action
func (m *RegexMatcher) Match(s string) (Action, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.patterns {
		if p.regex.MatchString(s) {
			return p.action, true
		}
	}

	return Allow, false
}

// MatchFirst returns the first matching pattern
func (m *RegexMatcher) MatchFirst(s string) *compiledPattern {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.patterns {
		if p.regex.MatchString(s) {
			return p
		}
	}

	return nil
}

// Clear removes all patterns
func (m *RegexMatcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patterns = make([]*compiledPattern, 0)
}

// Count returns the number of patterns
func (m *RegexMatcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.patterns)
}

// DomainRegexMatcher provides domain-specific regex matching
type DomainRegexMatcher struct {
	*RegexMatcher
}

// NewDomainRegexMatcher creates a new domain regex matcher
func NewDomainRegexMatcher() *DomainRegexMatcher {
	return &DomainRegexMatcher{
		RegexMatcher: NewRegexMatcher(),
	}
}

// AddDomainPattern adds a domain pattern
// Supports wildcards: *.example.com, example.*, *.example.*
func (m *DomainRegexMatcher) AddDomainPattern(pattern string, action Action) error {
	// Convert wildcard pattern to regex
	regexPattern := wildcardToRegex(pattern)
	return m.AddPattern(regexPattern, action)
}

// AddDomainPatterns adds multiple domain patterns
func (m *DomainRegexMatcher) AddDomainPatterns(patterns []string, action Action) error {
	for _, pattern := range patterns {
		if err := m.AddDomainPattern(pattern, action); err != nil {
			return err
		}
	}
	return nil
}

// MatchDomain matches a domain against patterns
func (m *DomainRegexMatcher) MatchDomain(domain string) (Action, bool) {
	// Normalize domain
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	return m.Match(domain)
}

// wildcardToRegex converts a wildcard pattern to a regex pattern
func wildcardToRegex(pattern string) string {
	// Escape special regex characters except *
	var result strings.Builder
	result.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			result.WriteString(".*")
		case '.':
			result.WriteString("\\.")
		case '?':
			result.WriteString(".")
		case '[', ']', '(', ')', '{', '}', '+', '^', '$', '|', '\\':
			result.WriteByte('\\')
			result.WriteByte(c)
		default:
			result.WriteByte(c)
		}
	}

	result.WriteString("$")
	return result.String()
}

// RegexRuleEngine implements RuleEngine with regex-based rules
type RegexRuleEngine struct {
	domainMatcher *DomainRegexMatcher
	hostMatcher   *RegexMatcher
	defaultAction Action
}

// NewRegexRuleEngine creates a new regex rule engine
func NewRegexRuleEngine(defaultAction Action) *RegexRuleEngine {
	return &RegexRuleEngine{
		domainMatcher: NewDomainRegexMatcher(),
		hostMatcher:   NewRegexMatcher(),
		defaultAction: defaultAction,
	}
}

// AddDomainRule adds a domain rule with wildcard support
func (e *RegexRuleEngine) AddDomainRule(pattern string, action Action) error {
	return e.domainMatcher.AddDomainPattern(pattern, action)
}

// AddRegexRule adds a raw regex rule
func (e *RegexRuleEngine) AddRegexRule(pattern string, action Action) error {
	return e.hostMatcher.AddPattern(pattern, action)
}

// Decide implements RuleEngine
func (e *RegexRuleEngine) Decide(ctx context.Context, metadata Metadata) Action {
	// Check domain patterns first
	if action, matched := e.domainMatcher.MatchDomain(metadata.TargetHost); matched {
		return action
	}

	// Check raw regex patterns
	if action, matched := e.hostMatcher.Match(metadata.TargetHost); matched {
		return action
	}

	return e.defaultAction
}

// CompositeRuleEngine combines multiple rule engines
type CompositeRuleEngine struct {
	engines       []RuleEngine
	defaultAction Action
}

// NewCompositeRuleEngine creates a new composite rule engine
func NewCompositeRuleEngine(defaultAction Action) *CompositeRuleEngine {
	return &CompositeRuleEngine{
		engines:       make([]RuleEngine, 0),
		defaultAction: defaultAction,
	}
}

// AddEngine adds a rule engine
func (e *CompositeRuleEngine) AddEngine(engine RuleEngine) {
	e.engines = append(e.engines, engine)
}

// Decide implements RuleEngine
// Returns the first non-default action from any engine
func (e *CompositeRuleEngine) Decide(ctx context.Context, metadata Metadata) Action {
	for _, engine := range e.engines {
		action := engine.Decide(ctx, metadata)
		// If any engine returns Block, immediately block
		if action == Block {
			return Block
		}
		// If any engine returns a specific action (not the default), use it
		if action != e.defaultAction {
			return action
		}
	}
	return e.defaultAction
}

// CommonDomainPatterns provides common domain patterns
var CommonDomainPatterns = struct {
	Ads         []string
	Trackers    []string
	Malware     []string
	SocialMedia []string
	Streaming   []string
}{
	Ads: []string{
		"*.doubleclick.net",
		"*.googlesyndication.com",
		"*.googleadservices.com",
		"*.google-analytics.com",
		"*.adnxs.com",
		"*.adsrvr.org",
		"*.adform.net",
		"*.advertising.com",
	},
	Trackers: []string{
		"*.facebook.com/tr/*",
		"*.google-analytics.com",
		"*.hotjar.com",
		"*.mixpanel.com",
		"*.segment.io",
		"*.amplitude.com",
	},
	Malware: []string{
		"*.malware.com",
		"*.phishing.com",
	},
	SocialMedia: []string{
		"*.facebook.com",
		"*.twitter.com",
		"*.instagram.com",
		"*.tiktok.com",
		"*.snapchat.com",
	},
	Streaming: []string{
		"*.netflix.com",
		"*.youtube.com",
		"*.twitch.tv",
		"*.hulu.com",
		"*.disneyplus.com",
	},
}

// GFWListMatcher matches domains against GFWList-style rules
type GFWListMatcher struct {
	mu       sync.RWMutex
	domains  map[string]bool   // Exact domain matches
	suffixes []string          // Domain suffix matches
	regexes  []*regexp.Regexp  // Regex matches
	keywords []string          // Keyword matches
}

// NewGFWListMatcher creates a new GFWList matcher
func NewGFWListMatcher() *GFWListMatcher {
	return &GFWListMatcher{
		domains:  make(map[string]bool),
		suffixes: make([]string, 0),
		regexes:  make([]*regexp.Regexp, 0),
		keywords: make([]string, 0),
	}
}

// AddRule adds a GFWList-style rule
// Supports formats:
// - example.com (exact match)
// - .example.com (suffix match)
// - ||example.com (domain match)
// - /regex/ (regex match)
// - keyword (keyword match)
func (m *GFWListMatcher) AddRule(rule string) error {
	rule = strings.TrimSpace(rule)
	if rule == "" || strings.HasPrefix(rule, "!") || strings.HasPrefix(rule, "[") {
		// Skip empty lines, comments, and section headers
		return nil
	}

	// Remove exception marker (we don't support exceptions yet)
	if strings.HasPrefix(rule, "@@") {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Regex rule
	if strings.HasPrefix(rule, "/") && strings.HasSuffix(rule, "/") {
		pattern := rule[1 : len(rule)-1]
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		m.regexes = append(m.regexes, regex)
		return nil
	}

	// Domain match (||example.com)
	if strings.HasPrefix(rule, "||") {
		domain := strings.TrimPrefix(rule, "||")
		domain = strings.TrimSuffix(domain, "^")
		m.suffixes = append(m.suffixes, "."+domain)
		m.domains[domain] = true
		return nil
	}

	// Suffix match (.example.com)
	if strings.HasPrefix(rule, ".") {
		m.suffixes = append(m.suffixes, rule)
		return nil
	}

	// URL pattern (|http://...)
	if strings.HasPrefix(rule, "|") {
		// Convert to keyword
		keyword := strings.TrimPrefix(rule, "|")
		m.keywords = append(m.keywords, keyword)
		return nil
	}

	// Default: treat as keyword
	m.keywords = append(m.keywords, rule)
	return nil
}

// LoadRules loads multiple rules
func (m *GFWListMatcher) LoadRules(rules []string) error {
	for _, rule := range rules {
		if err := m.AddRule(rule); err != nil {
			return err
		}
	}
	return nil
}

// Match checks if a domain/URL matches any rule
func (m *GFWListMatcher) Match(s string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s = strings.ToLower(s)

	// Exact domain match
	if m.domains[s] {
		return true
	}

	// Suffix match
	for _, suffix := range m.suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}

	// Regex match
	for _, regex := range m.regexes {
		if regex.MatchString(s) {
			return true
		}
	}

	// Keyword match
	for _, keyword := range m.keywords {
		if strings.Contains(s, keyword) {
			return true
		}
	}

	return false
}

// Count returns the total number of rules
func (m *GFWListMatcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domains) + len(m.suffixes) + len(m.regexes) + len(m.keywords)
}
