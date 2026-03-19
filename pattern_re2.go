package grokky

import (
	"strings"

	"github.com/wasilibs/go-re2"
)

// PatternRe2 is a compiled grok pattern using the RE2 regexp engine.
type PatternRe2 struct {
	*re2.Regexp
	s                map[string]int
	requiredLiterals []string // literals that must appear in any matching input
}

// canMatch performs cheap pre-checks to determine if the input could possibly match.
// Returns false if the input definitely cannot match (fast rejection).
func (p *PatternRe2) canMatch(input string) bool {
	for _, lit := range p.requiredLiterals {
		if !strings.Contains(input, lit) {
			return false
		}
	}
	return true
}

// Parse returns map (name->match) on input. The map can be empty.
func (p *PatternRe2) Parse(input string) map[string]string {
	// Fast-reject: check required literals before running the regex engine
	if !p.canMatch(input) {
		return make(map[string]string)
	}

	ss := p.FindStringSubmatch(input)
	r := make(map[string]string)
	if len(ss) <= 1 {
		return r
	}
	for sem, order := range p.s {
		r[sem] = ss[order]
	}
	return r
}

// ParseInto writes matched captures directly into the provided dest map,
// avoiding the intermediate map allocation of Parse(). Returns true if the
// pattern matched and captures were written.
func (p *PatternRe2) ParseInto(input string, dest map[string]string) bool {
	if !p.canMatch(input) {
		return false
	}

	ss := p.FindStringSubmatch(input)
	if len(ss) <= 1 {
		return false
	}
	for sem, order := range p.s {
		dest[sem] = ss[order]
	}
	return true
}

// Names returns all names that this pattern has
func (p *PatternRe2) Names() (ss []string) {
	ss = make([]string, 0, len(p.s))
	for k := range p.s {
		ss = append(ss, k)
	}
	return
}
