package grokky

import (
	"regexp/syntax"
	"strings"
)

// minLiteralLength is the minimum length of a literal to be considered for fast-reject.
// Shorter literals have higher false-positive rates, diminishing their value as pre-filters.
const minLiteralLength = 3

// extractRequiredLiterals parses a regex pattern string and extracts literal substrings
// that MUST appear in any matching input. This enables fast rejection of non-matching
// inputs with cheap strings.Contains() checks before running the full regex engine.
//
// The function walks the regexp/syntax AST and collects literals from OpConcat (sequence)
// nodes. Literals inside OpAlternate (alternation) nodes are excluded since only one
// branch needs to match. Literals inside optional repetitions (*, ?) are excluded since
// they may not appear in a valid match.
func extractRequiredLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()

	literals := collectLiterals(re)

	// Deduplicate and filter short literals
	seen := make(map[string]struct{})
	var result []string
	for _, lit := range literals {
		if len(lit) < minLiteralLength {
			continue
		}
		if _, ok := seen[lit]; ok {
			continue
		}
		seen[lit] = struct{}{}
		result = append(result, lit)
	}

	// Remove literals that are substrings of other literals in the set
	// (checking the longer one is sufficient)
	result = removeRedundantLiterals(result)

	return result
}

// collectLiterals recursively walks the regex AST and returns literal strings
// that must appear in any matching input.
func collectLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		lit := string(re.Rune)
		// Case-insensitive literals are not reliable for Contains() checks
		if re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		return []string{lit}

	case syntax.OpConcat:
		// In a concatenation, ALL children must match. Collect literals from each.
		// Also merge adjacent literals into longer strings.
		var allLiterals []string
		var adjacentLiteral strings.Builder

		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral && sub.Flags&syntax.FoldCase == 0 {
				adjacentLiteral.WriteString(string(sub.Rune))
			} else {
				if adjacentLiteral.Len() > 0 {
					allLiterals = append(allLiterals, adjacentLiteral.String())
					adjacentLiteral.Reset()
				}
				allLiterals = append(allLiterals, collectLiterals(sub)...)
			}
		}
		if adjacentLiteral.Len() > 0 {
			allLiterals = append(allLiterals, adjacentLiteral.String())
		}
		return allLiterals

	case syntax.OpCapture:
		// A capture group is transparent — recurse into the child.
		if len(re.Sub) > 0 {
			return collectLiterals(re.Sub[0])
		}
		return nil

	case syntax.OpRepeat:
		// Only recurse if the minimum repeat count is >= 1 (the literal must appear)
		if re.Min >= 1 && len(re.Sub) > 0 {
			return collectLiterals(re.Sub[0])
		}
		return nil

	case syntax.OpPlus:
		// x+ requires at least one occurrence
		if len(re.Sub) > 0 {
			return collectLiterals(re.Sub[0])
		}
		return nil

	case syntax.OpQuest, syntax.OpStar:
		// x? and x* don't require the literal to appear
		return nil

	case syntax.OpAlternate:
		// In an alternation (a|b|c), we cannot require any single branch's literals
		// because only one branch needs to match.
		return nil

	default:
		// OpAnyChar, OpAnyCharNotNL, OpCharClass, OpEmptyMatch,
		// OpBeginLine, OpEndLine, OpBeginText, OpEndText,
		// OpWordBoundary, OpNoWordBoundary, OpNoMatch
		return nil
	}
}

// removeRedundantLiterals removes literals that are substrings of other literals in the set.
// If "Failed password" and "password" are both required, checking "Failed password" is sufficient.
func removeRedundantLiterals(literals []string) []string {
	if len(literals) <= 1 {
		return literals
	}

	var result []string
	for i, a := range literals {
		redundant := false
		for j, b := range literals {
			if i != j && len(b) > len(a) && strings.Contains(b, a) {
				redundant = true
				break
			}
		}
		if !redundant {
			result = append(result, a)
		}
	}
	return result
}
