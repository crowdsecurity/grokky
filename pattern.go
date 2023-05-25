package grokky

type Pattern interface {
	FindStringSubmatch(s string) []string
	String() string
	Names() []string
	Parse(input string) map[string]string
	NumSubexp() int
	//ripped from regexp.Regexp
	Match([]byte) bool
	FindStringIndex(string) (loc []int)
	FindAllStringSubmatchIndex(s string, n int) [][]int
	FindAllStringSubmatch(s string, n int) [][]string
}
