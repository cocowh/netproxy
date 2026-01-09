package router

import (
	"strings"

	"github.com/cocowh/netproxy/internal/feature/acl"
)

type TrieNode struct {
	children map[string]*TrieNode
	action   acl.Action
	hasRule  bool
}

// NewTrie creates a new Trie
func NewTrie() *TrieNode {
	return &TrieNode{
		children: make(map[string]*TrieNode),
	}
}

// Insert adds a domain to the Trie
// We store domains in reverse order (com.google.www) to match suffixes effectively
func (t *TrieNode) Insert(domain string, action acl.Action) {
	parts := strings.Split(domain, ".")
	node := t
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if _, ok := node.children[part]; !ok {
			node.children[part] = NewTrie()
		}
		node = node.children[part]
	}
	node.action = action
	node.hasRule = true
}

// Search checks if the domain or any of its suffixes exist in the Trie
// Returns true if a match is found
func (t *TrieNode) Search(domain string) (acl.Action, bool) {
	parts := strings.Split(domain, ".")
	node := t

	// We iterate from end to start (com -> google -> www)
	// But matching should favor the most specific rule?
	// E.g. "google.com" -> PROXY, "mail.google.com" -> DIRECT.
	// If we have "mail.google.com", we match "com", "google", "mail".
	// We hit "google" (isEnd=true, action=PROXY).
	// We hit "mail" (isEnd=true, action=DIRECT).
	// We should return the deepest match.

	var lastAction acl.Action
	var found bool

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		child, ok := node.children[part]
		if !ok {
			break
		}

		node = child
		if node.hasRule {
			lastAction = node.action
			found = true
		}
	}

	return lastAction, found
}
