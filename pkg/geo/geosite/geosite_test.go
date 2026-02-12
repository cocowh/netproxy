package geosite

import (
	"strings"
	"testing"
)

func TestGeoSite(t *testing.T) {
	t.Run("LoadFromReader", func(t *testing.T) {
		data := `
# Comment line
google:domain:google.com
google:domain:googleapis.com
google:full:www.google.com
cn:domain:baidu.com@cn
cn:domain:qq.com@cn,ads
ads:keyword:ad
ads:keyword:tracker
`
		g := New()
		err := g.LoadFromReader(strings.NewReader(data))
		if err != nil {
			t.Fatalf("LoadFromReader failed: %v", err)
		}

		categories := g.Categories()
		if len(categories) != 3 {
			t.Errorf("Expected 3 categories, got %d", len(categories))
		}

		if g.RuleCount() != 7 {
			t.Errorf("Expected 7 rules, got %d", g.RuleCount())
		}
	})

	t.Run("Match_Domain", func(t *testing.T) {
		g := New()
		g.AddCategory("google", []*Rule{
			{Type: MatchTypeDomain, Value: "google.com"},
			{Type: MatchTypeDomain, Value: "googleapis.com"},
		})

		// Exact match
		if !g.Match("google.com", "google") {
			t.Error("Should match google.com")
		}

		// Subdomain match
		if !g.Match("www.google.com", "google") {
			t.Error("Should match www.google.com")
		}

		if !g.Match("api.googleapis.com", "google") {
			t.Error("Should match api.googleapis.com")
		}

		// Should not match
		if g.Match("notgoogle.com", "google") {
			t.Error("Should not match notgoogle.com")
		}

		if g.Match("google.com.cn", "google") {
			t.Error("Should not match google.com.cn")
		}
	})

	t.Run("Match_Full", func(t *testing.T) {
		g := New()
		g.AddCategory("exact", []*Rule{
			{Type: MatchTypeFull, Value: "www.example.com"},
		})

		if !g.Match("www.example.com", "exact") {
			t.Error("Should match www.example.com exactly")
		}

		if g.Match("example.com", "exact") {
			t.Error("Should not match example.com")
		}

		if g.Match("sub.www.example.com", "exact") {
			t.Error("Should not match subdomain")
		}
	})

	t.Run("Match_Plain", func(t *testing.T) {
		g := New()
		g.AddCategory("ads", []*Rule{
			{Type: MatchTypePlain, Value: "ad"},
			{Type: MatchTypePlain, Value: "tracker"},
		})

		if !g.Match("ads.example.com", "ads") {
			t.Error("Should match ads.example.com")
		}

		if !g.Match("example-ad.com", "ads") {
			t.Error("Should match example-ad.com")
		}

		if !g.Match("tracker.example.com", "ads") {
			t.Error("Should match tracker.example.com")
		}

		if g.Match("example.com", "ads") {
			t.Error("Should not match example.com")
		}
	})

	t.Run("Match_MultipleCategories", func(t *testing.T) {
		g := New()
		g.AddCategory("google", []*Rule{
			{Type: MatchTypeDomain, Value: "google.com"},
		})
		g.AddCategory("cn", []*Rule{
			{Type: MatchTypeDomain, Value: "baidu.com"},
		})

		if !g.Match("google.com", "google", "cn") {
			t.Error("Should match google.com in google category")
		}

		if !g.Match("baidu.com", "google", "cn") {
			t.Error("Should match baidu.com in cn category")
		}

		if g.Match("example.com", "google", "cn") {
			t.Error("Should not match example.com")
		}
	})

	t.Run("Match_NonexistentCategory", func(t *testing.T) {
		g := New()

		if g.Match("example.com", "nonexistent") {
			t.Error("Should not match in nonexistent category")
		}
	})

	t.Run("MatchWithAttr", func(t *testing.T) {
		g := New()
		g.AddCategory("cn", []*Rule{
			{Type: MatchTypeDomain, Value: "baidu.com", Attrs: map[string]string{"cn": ""}},
			{Type: MatchTypeDomain, Value: "qq.com", Attrs: map[string]string{"cn": "", "ads": ""}},
			{Type: MatchTypeDomain, Value: "example.cn", Attrs: map[string]string{}},
		})

		if !g.MatchWithAttr("baidu.com", "cn", "cn") {
			t.Error("Should match baidu.com with @cn")
		}

		if !g.MatchWithAttr("qq.com", "ads", "cn") {
			t.Error("Should match qq.com with @ads")
		}

		if g.MatchWithAttr("example.cn", "cn", "cn") {
			t.Error("Should not match example.cn without @cn attr")
		}
	})

	t.Run("GetCategory", func(t *testing.T) {
		g := New()
		g.AddCategory("test", []*Rule{
			{Type: MatchTypeDomain, Value: "test.com"},
		})

		cat, ok := g.GetCategory("test")
		if !ok {
			t.Error("Should find test category")
		}
		if cat.Name != "test" {
			t.Errorf("Expected name 'test', got '%s'", cat.Name)
		}
		if len(cat.Rules) != 1 {
			t.Errorf("Expected 1 rule, got %d", len(cat.Rules))
		}

		_, ok = g.GetCategory("nonexistent")
		if ok {
			t.Error("Should not find nonexistent category")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		g := New()
		g.AddCategory("test", []*Rule{
			{Type: MatchTypeDomain, Value: "test.com"},
		})

		g.Clear()

		if len(g.Categories()) != 0 {
			t.Error("Categories should be empty after clear")
		}

		if g.RuleCount() != 0 {
			t.Error("Rule count should be 0 after clear")
		}
	})

	t.Run("CaseInsensitive", func(t *testing.T) {
		g := New()
		g.AddCategory("test", []*Rule{
			{Type: MatchTypeDomain, Value: "example.com"},
		})

		if !g.Match("EXAMPLE.COM", "test") {
			t.Error("Should match case-insensitively")
		}

		if !g.Match("Example.Com", "test") {
			t.Error("Should match mixed case")
		}
	})
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		line         string
		wantCategory string
		wantType     MatchType
		wantValue    string
		wantAttrs    map[string]string
		wantErr      bool
	}{
		{
			line:         "google:domain:google.com",
			wantCategory: "google",
			wantType:     MatchTypeDomain,
			wantValue:    "google.com",
			wantAttrs:    map[string]string{},
		},
		{
			line:         "cn:full:baidu.com@cn",
			wantCategory: "cn",
			wantType:     MatchTypeFull,
			wantValue:    "baidu.com",
			wantAttrs:    map[string]string{"cn": ""},
		},
		{
			line:         "ads:keyword:tracker@ads,malware",
			wantCategory: "ads",
			wantType:     MatchTypePlain,
			wantValue:    "tracker",
			wantAttrs:    map[string]string{"ads": "", "malware": ""},
		},
		{
			line:         "simple:example.com",
			wantCategory: "simple",
			wantType:     MatchTypeDomain,
			wantValue:    "example.com",
			wantAttrs:    map[string]string{},
		},
		{
			line:    "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			rule, category, err := parseLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if category != tt.wantCategory {
				t.Errorf("Category: got %s, want %s", category, tt.wantCategory)
			}

			if rule.Type != tt.wantType {
				t.Errorf("Type: got %d, want %d", rule.Type, tt.wantType)
			}

			if rule.Value != tt.wantValue {
				t.Errorf("Value: got %s, want %s", rule.Value, tt.wantValue)
			}

			if len(rule.Attrs) != len(tt.wantAttrs) {
				t.Errorf("Attrs length: got %d, want %d", len(rule.Attrs), len(tt.wantAttrs))
			}

			for k := range tt.wantAttrs {
				if _, ok := rule.Attrs[k]; !ok {
					t.Errorf("Missing attr: %s", k)
				}
			}
		})
	}
}

func BenchmarkMatch(b *testing.B) {
	g := New()
	
	// Add many rules
	rules := make([]*Rule, 1000)
	for i := 0; i < 1000; i++ {
		rules[i] = &Rule{
			Type:  MatchTypeDomain,
			Value: strings.Repeat("a", i%10+1) + ".com",
		}
	}
	g.AddCategory("benchmark", rules)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Match("test.aaaaaaaaaa.com", "benchmark")
	}
}
