package grokky

type Pattern interface {
	String() string
	Names() []string
	Parse(input string) map[string]string
	NumSubexp() int
	//ripped from regexp.Regexp
	Match([]byte) bool
	FindStringIndex(string) (loc []int)

	FindAllStringSubmatchIndex(s string, n int) [][]int
	FindStringSubmatchIndex(s string) []int

	FindAllStringSubmatch(s string, n int) [][]string
	FindStringSubmatch(s string) []string
	SubexpIndex(name string) int
	SubexpNames() []string
}
