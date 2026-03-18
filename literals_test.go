package grokky

import (
	"sort"
	"testing"
)

func TestExtractRequiredLiterals(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected []string
	}{
		{
			name:     "simple literal",
			pattern:  `Failed password`,
			expected: []string{"Failed password"},
		},
		{
			name:     "literal with regex parts",
			pattern:  `Failed \w+ for \w+ from \d+\.\d+\.\d+\.\d+`,
			expected: []string{"Failed ", " for ", " from "},
		},
		{
			name:     "alternation excludes branch literals",
			pattern:  `(?:GET|POST|PUT) /api/`,
			expected: []string{" /api/"},
		},
		{
			name:     "no literals (pure regex)",
			pattern:  `\d+\.\d+\.\d+`,
			expected: nil,
		},
		{
			name:     "short literals filtered out",
			pattern:  `a\d+b\d+c`,
			expected: nil, // all literals < 3 chars
		},
		{
			name:     "capture group transparency",
			pattern:  `Failed (\w+) for (\w+)`,
			expected: []string{"Failed ", " for "},
		},
		{
			name:     "optional parts excluded",
			pattern:  `Error(?:\s+fatal)?\s+in module`,
			expected: []string{"Error", "in module"},
		},
		{
			name:     "star repetition excluded",
			pattern:  `prefix\w*suffix`,
			expected: []string{"prefix", "suffix"},
		},
		{
			name:     "plus repetition with literal",
			pattern:  `begin\w+end`,
			expected: []string{"begin", "end"},
		},
		{
			name:     "redundant literals removed",
			pattern:  `Failed password for invalid user`,
			expected: []string{"Failed password for invalid user"},
		},
		{
			name:     "case insensitive literal skipped",
			pattern:  `(?i)failed`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRequiredLiterals(tt.pattern)

			// Sort both for stable comparison
			sort.Strings(got)
			sort.Strings(tt.expected)

			if len(got) != len(tt.expected) {
				t.Errorf("extractRequiredLiterals(%q) = %v (len %d), want %v (len %d)",
					tt.pattern, got, len(got), tt.expected, len(tt.expected))
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("extractRequiredLiterals(%q)[%d] = %q, want %q",
						tt.pattern, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestFastReject_Parse(t *testing.T) {
	h := New()
	h.Must("WORD", `\b\w+\b`)
	h.Must("IP", `\d+\.\d+\.\d+\.\d+`)
	h.Must("SSHFAIL", `Failed %{WORD:method} for %{WORD:user} from %{IP:ip}`)

	p, err := h.Get("SSHFAIL")
	if err != nil {
		t.Fatal(err)
	}

	// Should match
	result := p.Parse("Failed password for root from 192.168.1.1")
	if len(result) == 0 {
		t.Error("expected match, got empty result")
	}
	if result["method"] != "password" {
		t.Errorf("method = %q, want %q", result["method"], "password")
	}
	if result["user"] != "root" {
		t.Errorf("user = %q, want %q", result["user"], "root")
	}

	// Should be fast-rejected (no "Failed" literal)
	result = p.Parse("Accepted password for root from 192.168.1.1")
	if len(result) != 0 {
		t.Error("expected fast-reject (no match), got:", result)
	}

	// Should be fast-rejected (no "from" literal)
	result = p.Parse("Failed password for root via 192.168.1.1")
	if len(result) != 0 {
		t.Error("expected no match, got:", result)
	}
}

func TestFastReject_ParseInto(t *testing.T) {
	h := New()
	h.Must("WORD", `\b\w+\b`)
	h.Must("IP", `\d+\.\d+\.\d+\.\d+`)
	h.Must("SSHFAIL", `Failed %{WORD:method} for %{WORD:user} from %{IP:ip}`)

	p, err := h.Get("SSHFAIL")
	if err != nil {
		t.Fatal(err)
	}

	// Should match
	dest := make(map[string]string)
	ok := p.ParseInto("Failed password for root from 192.168.1.1", dest)
	if !ok {
		t.Error("expected match, got false")
	}
	if dest["method"] != "password" {
		t.Errorf("method = %q, want %q", dest["method"], "password")
	}
	if dest["user"] != "root" {
		t.Errorf("user = %q, want %q", dest["user"], "root")
	}
	if dest["ip"] != "192.168.1.1" {
		t.Errorf("ip = %q, want %q", dest["ip"], "192.168.1.1")
	}

	// Should be fast-rejected
	dest2 := make(map[string]string)
	ok = p.ParseInto("Accepted password for root from 192.168.1.1", dest2)
	if ok {
		t.Error("expected fast-reject, got true")
	}
	if len(dest2) != 0 {
		t.Error("expected empty dest on fast-reject, got:", dest2)
	}
}

func TestParseInto_equivalence(t *testing.T) {
	// Verify ParseInto produces identical results to Parse
	h := New()
	h.Must("WORD", `\b\w+\b`)
	h.Must("NS", `[^\s]+`)
	h.Must("NQ", `[^"]+`)
	h.Must("NLB", `[^\]]+`)
	h.Must("A", `.*`)
	h.Must("NSS", `[^\s]*`)
	h.Must("nginx", `%{NS:clientip}\s%{NSS:ident}\s%{NSS:auth}`+
		`\s\[`+
		`%{NLB:timestamp}\]\s\"`+
		`%{NS:verb}\s`+
		`%{NSS:request}\s`+
		`HTTP/%{NS:httpversion}\"\s`+
		`%{NS:response}\s`+
		`%{NS:bytes}\s\"`+
		`%{NQ:referrer}\"\s\"`+
		`%{NQ:agent}\"`+
		`%{A:blob}`)

	p, err := h.Get("nginx")
	if err != nil {
		t.Fatal(err)
	}

	input := `66.249.65.159 - - [06/Nov/2014:19:10:38 +0600] ` +
		`"GET /news/53f8d72920ba2744fe873ebc.html HTTP/1.1" ` +
		`404 177 "-" ` +
		`"Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) ` +
		`AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 ` +
		`Mobile/10A5376e Safari/8536.25"`

	parseResult := p.Parse(input)
	dest := make(map[string]string)
	ok := p.ParseInto(input, dest)

	if !ok {
		t.Fatal("ParseInto returned false for matching input")
	}

	if len(parseResult) != len(dest) {
		t.Errorf("Parse returned %d entries, ParseInto wrote %d entries",
			len(parseResult), len(dest))
	}

	for k, v := range parseResult {
		if dest[k] != v {
			t.Errorf("key %q: Parse=%q, ParseInto=%q", k, v, dest[k])
		}
	}
}

func TestFastReject_noFalseNegatives(t *testing.T) {
	// Ensure the fast-reject never produces false negatives (rejecting a valid match)
	h := NewBase()
	h.Must("SYSLOGBASE2", `(?:%{SYSLOGTIMESTAMP:timestamp}|%{TIMESTAMP_ISO8601:timestamp8601}) (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:`)

	p, err := h.Get("SYSLOGBASE2")
	if err != nil {
		t.Fatal(err)
	}

	inputs := []string{
		`Jan 14 06:35:01 hostname CRON[12345]: pam_unix(cron:session): session opened`,
		`2024-01-14T06:35:01+00:00 hostname sshd[1234]: Accepted publickey`,
	}

	for _, input := range inputs {
		result := p.Parse(input)
		if len(result) == 0 {
			t.Errorf("false negative on %q: expected match, got none", input)
		}
	}
}

func BenchmarkFastReject_miss(b *testing.B) {
	h := New()
	h.Must("WORD", `\b\w+\b`)
	h.Must("IP", `\d+\.\d+\.\d+\.\d+`)
	h.Must("NUMBER", `\d+`)
	h.Must("SSHFAIL", `Failed %{WORD:method} for %{WORD:user} from %{IP:ip} port %{NUMBER:port}`)

	p, err := h.Get("SSHFAIL")
	if err != nil {
		b.Fatal(err)
	}

	// Input that does NOT match — should be fast-rejected by literal check
	nonMatchingInput := "Accepted publickey for admin from 10.0.0.1 port 22 ssh2"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		globalMap = p.Parse(nonMatchingInput)
	}
	b.ReportAllocs()
}

func BenchmarkFastReject_hit(b *testing.B) {
	h := New()
	h.Must("WORD", `\b\w+\b`)
	h.Must("IP", `\d+\.\d+\.\d+\.\d+`)
	h.Must("NUMBER", `\d+`)
	h.Must("SSHFAIL", `Failed %{WORD:method} for %{WORD:user} from %{IP:ip} port %{NUMBER:port}`)

	p, err := h.Get("SSHFAIL")
	if err != nil {
		b.Fatal(err)
	}

	// Input that DOES match
	matchingInput := "Failed password for root from 192.168.1.1 port 22"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		globalMap = p.Parse(matchingInput)
	}
	b.ReportAllocs()
}

func BenchmarkParseInto_hit(b *testing.B) {
	h := New()
	h.Must("WORD", `\b\w+\b`)
	h.Must("IP", `\d+\.\d+\.\d+\.\d+`)
	h.Must("NUMBER", `\d+`)
	h.Must("SSHFAIL", `Failed %{WORD:method} for %{WORD:user} from %{IP:ip} port %{NUMBER:port}`)

	p, err := h.Get("SSHFAIL")
	if err != nil {
		b.Fatal(err)
	}

	matchingInput := "Failed password for root from 192.168.1.1 port 22"
	dest := make(map[string]string)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clear dest between iterations
		for k := range dest {
			delete(dest, k)
		}
		p.ParseInto(matchingInput, dest)
	}
	b.ReportAllocs()
}

func BenchmarkParseInto_miss(b *testing.B) {
	h := New()
	h.Must("WORD", `\b\w+\b`)
	h.Must("IP", `\d+\.\d+\.\d+\.\d+`)
	h.Must("NUMBER", `\d+`)
	h.Must("SSHFAIL", `Failed %{WORD:method} for %{WORD:user} from %{IP:ip} port %{NUMBER:port}`)

	p, err := h.Get("SSHFAIL")
	if err != nil {
		b.Fatal(err)
	}

	nonMatchingInput := "Accepted publickey for admin from 10.0.0.1 port 22 ssh2"
	dest := make(map[string]string)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ParseInto(nonMatchingInput, dest)
	}
	b.ReportAllocs()
}
