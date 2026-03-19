package grokky

import (
	"regexp"
	"strings"
)

// PatternLegacy is a compiled grok pattern using Go's standard regexp engine.
type PatternLegacy struct {
	*regexp.Regexp
	s                map[string]int
	requiredLiterals []string // literals that must appear in any matching input
}

// canMatch performs cheap pre-checks to determine if the input could possibly match.
// Returns false if the input definitely cannot match (fast rejection).
func (p *PatternLegacy) canMatch(input string) bool {
	for _, lit := range p.requiredLiterals {
		if !strings.Contains(input, lit) {
			return false
		}
	}
	return true
}

// Parse returns map (name->match) on input. The map can be empty.
func (p *PatternLegacy) Parse(input string) map[string]string {
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
func (p *PatternLegacy) ParseInto(input string, dest map[string]string) bool {
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
func (p *PatternLegacy) Names() (ss []string) {
	ss = make([]string, 0, len(p.s))
	for k := range p.s {
		ss = append(ss, k)
	}
	return
}
