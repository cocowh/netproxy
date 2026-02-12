package fakedns

import (
	"net"
	"testing"
	"time"
)

func TestPool(t *testing.T) {
	t.Run("NewPool", func(t *testing.T) {
		pool, err := NewPool("198.18.0.0/16")
		if err != nil {
			t.Fatalf("NewPool failed: %v", err)
		}

		if pool.Size() != 65536 {
			t.Errorf("Expected size 65536, got %d", pool.Size())
		}
	})

	t.Run("Allocate", func(t *testing.T) {
		pool, _ := NewPool("198.18.0.0/24")

		ip1, err := pool.Allocate()
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}

		if !pool.Contains(ip1) {
			t.Errorf("Pool should contain allocated IP %s", ip1)
		}

		ip2, _ := pool.Allocate()
		if ip1.Equal(ip2) {
			t.Error("Second allocation should return different IP")
		}
	})

	t.Run("Contains", func(t *testing.T) {
		pool, _ := NewPool("198.18.0.0/16")

		if !pool.Contains(net.ParseIP("198.18.0.1")) {
			t.Error("Pool should contain 198.18.0.1")
		}

		if !pool.Contains(net.ParseIP("198.18.255.255")) {
			t.Error("Pool should contain 198.18.255.255")
		}

		if pool.Contains(net.ParseIP("198.19.0.1")) {
			t.Error("Pool should not contain 198.19.0.1")
		}

		if pool.Contains(net.ParseIP("192.168.1.1")) {
			t.Error("Pool should not contain 192.168.1.1")
		}
	})

	t.Run("WrapAround", func(t *testing.T) {
		pool, _ := NewPool("198.18.0.0/30") // Only 4 IPs

		seen := make(map[string]bool)
		for i := 0; i < 8; i++ {
			ip, _ := pool.Allocate()
			seen[ip.String()] = true
		}

		// Should have wrapped around
		if len(seen) > 4 {
			t.Errorf("Expected at most 4 unique IPs, got %d", len(seen))
		}
	})

	t.Run("InvalidCIDR", func(t *testing.T) {
		_, err := NewPool("invalid")
		if err == nil {
			t.Error("Expected error for invalid CIDR")
		}

		_, err = NewPool("2001:db8::/32")
		if err == nil {
			t.Error("Expected error for IPv6 CIDR")
		}
	})
}

func TestMapping(t *testing.T) {
	t.Run("GetOrCreate", func(t *testing.T) {
		m, err := NewMapping(&MappingConfig{
			IPv4CIDR: "198.18.0.0/24",
			MaxSize:  100,
			TTL:      time.Hour,
		})
		if err != nil {
			t.Fatalf("NewMapping failed: %v", err)
		}

		ip1, err := m.GetOrCreate("example.com")
		if err != nil {
			t.Fatalf("GetOrCreate failed: %v", err)
		}

		// Same domain should return same IP
		ip2, _ := m.GetOrCreate("example.com")
		if !ip1.Equal(ip2) {
			t.Errorf("Same domain should return same IP: %s vs %s", ip1, ip2)
		}

		// Different domain should return different IP
		ip3, _ := m.GetOrCreate("google.com")
		if ip1.Equal(ip3) {
			t.Error("Different domains should return different IPs")
		}
	})

	t.Run("Lookup", func(t *testing.T) {
		m, _ := NewMapping(nil)

		ip, _ := m.GetOrCreate("test.com")

		domain, ok := m.Lookup(ip)
		if !ok {
			t.Error("Lookup should find the domain")
		}
		if domain != "test.com" {
			t.Errorf("Expected test.com, got %s", domain)
		}

		// Non-existent IP
		_, ok = m.Lookup(net.ParseIP("1.2.3.4"))
		if ok {
			t.Error("Lookup should not find non-existent IP")
		}
	})

	t.Run("LookupIP", func(t *testing.T) {
		m, _ := NewMapping(nil)

		expectedIP, _ := m.GetOrCreate("lookup.test")

		ip, ok := m.LookupIP("lookup.test")
		if !ok {
			t.Error("LookupIP should find the IP")
		}
		if !ip.Equal(expectedIP) {
			t.Errorf("Expected %s, got %s", expectedIP, ip)
		}

		// Non-existent domain
		_, ok = m.LookupIP("nonexistent.test")
		if ok {
			t.Error("LookupIP should not find non-existent domain")
		}
	})

	t.Run("IsFakeIP", func(t *testing.T) {
		m, _ := NewMapping(&MappingConfig{
			IPv4CIDR: "198.18.0.0/16",
		})

		if !m.IsFakeIP(net.ParseIP("198.18.1.1")) {
			t.Error("198.18.1.1 should be a fake IP")
		}

		if m.IsFakeIP(net.ParseIP("8.8.8.8")) {
			t.Error("8.8.8.8 should not be a fake IP")
		}
	})

	t.Run("Remove", func(t *testing.T) {
		m, _ := NewMapping(nil)

		ip, _ := m.GetOrCreate("remove.test")
		m.Remove("remove.test")

		_, ok := m.Lookup(ip)
		if ok {
			t.Error("Removed domain should not be found")
		}

		_, ok = m.LookupIP("remove.test")
		if ok {
			t.Error("Removed domain should not be found by LookupIP")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		m, _ := NewMapping(nil)

		m.GetOrCreate("a.test")
		m.GetOrCreate("b.test")
		m.GetOrCreate("c.test")

		if m.Size() != 3 {
			t.Errorf("Expected size 3, got %d", m.Size())
		}

		m.Clear()

		if m.Size() != 0 {
			t.Errorf("Expected size 0 after clear, got %d", m.Size())
		}
	})

	t.Run("Eviction", func(t *testing.T) {
		m, _ := NewMapping(&MappingConfig{
			IPv4CIDR: "198.18.0.0/24",
			MaxSize:  3,
			TTL:      time.Hour,
		})

		m.GetOrCreate("a.test")
		m.GetOrCreate("b.test")
		m.GetOrCreate("c.test")

		// This should trigger eviction
		m.GetOrCreate("d.test")

		if m.Size() > 3 {
			t.Errorf("Size should not exceed max, got %d", m.Size())
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		m, _ := NewMapping(&MappingConfig{
			IPv4CIDR: "198.18.0.0/24",
			MaxSize:  100,
			TTL:      time.Millisecond * 10,
		})

		ip, _ := m.GetOrCreate("expire.test")

		// Should be found immediately
		_, ok := m.Lookup(ip)
		if !ok {
			t.Error("Should find IP immediately after creation")
		}

		// Wait for expiration
		time.Sleep(time.Millisecond * 20)

		// Should not be found after expiration
		_, ok = m.Lookup(ip)
		if ok {
			t.Error("Should not find IP after expiration")
		}
	})

	t.Run("Cleanup", func(t *testing.T) {
		m, _ := NewMapping(&MappingConfig{
			IPv4CIDR: "198.18.0.0/24",
			MaxSize:  100,
			TTL:      time.Millisecond * 10,
		})

		m.GetOrCreate("cleanup1.test")
		m.GetOrCreate("cleanup2.test")

		time.Sleep(time.Millisecond * 20)

		removed := m.Cleanup()
		if removed != 2 {
			t.Errorf("Expected 2 removed, got %d", removed)
		}
	})

	t.Run("Stats", func(t *testing.T) {
		m, _ := NewMapping(nil)

		m.GetOrCreate("stats1.test")
		m.GetOrCreate("stats2.test")

		stats := m.GetStats()
		if stats.TotalEntries != 2 {
			t.Errorf("Expected 2 total entries, got %d", stats.TotalEntries)
		}
		if stats.IPv4Entries != 2 {
			t.Errorf("Expected 2 IPv4 entries, got %d", stats.IPv4Entries)
		}
	})
}

func TestIPv6Pool(t *testing.T) {
	t.Run("NewIPv6Pool", func(t *testing.T) {
		pool, err := NewIPv6Pool("fc00::/64")
		if err != nil {
			t.Fatalf("NewIPv6Pool failed: %v", err)
		}

		ip, err := pool.Allocate()
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}

		if !pool.Contains(ip) {
			t.Errorf("Pool should contain allocated IP %s", ip)
		}
	})

	t.Run("InvalidIPv6CIDR", func(t *testing.T) {
		_, err := NewIPv6Pool("192.168.0.0/24")
		if err == nil {
			t.Error("Expected error for IPv4 CIDR")
		}
	})
}

func BenchmarkGetOrCreate(b *testing.B) {
	m, _ := NewMapping(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.GetOrCreate("benchmark.test")
	}
}

func BenchmarkLookup(b *testing.B) {
	m, _ := NewMapping(nil)
	ip, _ := m.GetOrCreate("benchmark.test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Lookup(ip)
	}
}
