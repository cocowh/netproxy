package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigWatch(t *testing.T) {
	// Create a temporary config file
	tmpFile, err := os.CreateTemp("", "config_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	initialConfig := `
routing:
  rules:
    - "domain:example.com"
`
	if _, err := tmpFile.WriteString(initialConfig); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}
	tmpFile.Close()

	// Initialize Manager
	m := NewManager(tmpFile.Name())
	if err := m.Load(); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	cfg := m.GetConfig()
	assert.Equal(t, 1, len(cfg.Routing.Rules))
	assert.Equal(t, "domain:example.com", cfg.Routing.Rules[0])

	// Channel to signal update
	updateChan := make(chan *Config)

	// Start Watching
	m.Watch(func(newCfg *Config) {
		updateChan <- newCfg
	})

	// Modify Config File
	updatedConfig := `
routing:
  rules:
    - "domain:example.com"
    - "domain:google.com"
`
	// Viper uses fsnotify which might have some delay or quirks depending on OS.
	// We wait a bit before writing to ensure watcher is ready.
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(tmpFile.Name(), []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	// Wait for update
	select {
	case newCfg := <-updateChan:
		assert.Equal(t, 2, len(newCfg.Routing.Rules))
		assert.Equal(t, "domain:google.com", newCfg.Routing.Rules[1])
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for config update")
	}
}
