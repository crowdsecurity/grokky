package grokky

type Pattern interface {
	FindStringSubmatch(s string) []string
	String() string
	Names() []string
	Parse(input string) map[string]string
	// ParseInto writes matched captures directly into dest, avoiding an intermediate
	// map allocation. Returns true if the pattern matched and captures were written.
	ParseInto(input string, dest map[string]string) bool
	NumSubexp() int
}
