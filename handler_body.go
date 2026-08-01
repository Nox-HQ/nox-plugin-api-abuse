package main

import (
	"regexp"
	"strings"
)

// API-ABUSE-001 matched a handler SIGNATURE and nothing else, so it reported
// "Missing authentication check on handler" — at high severity and high
// confidence — for the mere existence of an HTTP handler. Measured against
// nox's precision corpus it fired on 17 of 17 handlers, in the clean fixtures
// and the vulnerable ones alike, discriminating nothing.
//
// A handler with no authentication is not by itself a defect: public endpoints
// are legitimate and ubiquitous. What is worth reporting is a handler that
// READS OR CHANGES SOMETHING while no authentication is visible. That is the
// question these patterns ask.

// sensitiveOps are operations whose exposure without authentication is worth a
// second look: executing commands, touching the database, reading or writing
// files, and calling outbound services on the caller's behalf.
var sensitiveOps = map[string]*regexp.Regexp{
	// The database verbs are anchored to a database-ish receiver on purpose.
	// A bare `.Query(` also matches `r.URL.Query()` — reading a query string,
	// not touching a database — which silently turned this whole check into
	// "the handler reads a parameter", i.e. back to firing on everything.
	".go": regexp.MustCompile(`(?i)(exec\.Command|os\.(ReadFile|WriteFile|Open|Create|Remove)|\b(db|tx|conn|stmt|sqlDB|repo|store)\w*\.(Query|QueryRow|Exec|Find|Save|Delete|Insert|Update)\(|http\.(Get|Post|Do)\(|client\.Do\()`),
	".py": regexp.MustCompile(`(?i)(os\.system|subprocess\.|open\(|\.execute\(|\.query\(|session\.(add|delete|commit)|requests\.(get|post|put|delete))`),
	".js": regexp.MustCompile(`(?i)(child_process|fs\.(readFile|writeFile|unlink)|\.query\(|\.find\(|\.save\(|\.deleteOne\(|fetch\(|axios\.)`),
	".ts": regexp.MustCompile(`(?i)(child_process|fs\.(readFile|writeFile|unlink)|\.query\(|\.find\(|\.save\(|\.deleteOne\(|fetch\(|axios\.)`),
}

// funcStartRE marks the beginning of a new top-level declaration, used as the
// end boundary of the handler body. Brace matching would be more precise, but
// it is defeated by braces in strings and comments; overrunning into the next
// function can only make this rule MORE likely to fire, never less, so the
// conservative direction is preserved.
var funcStartRE = regexp.MustCompile(`^(func |def |async def |@app\.|@router\.)`)

// maxHandlerBodyLines bounds the scan so one unterminated declaration cannot
// turn into a whole-file search.
const maxHandlerBodyLines = 120

// handlerBodyIsSensitive reports whether the handler beginning at lines[start]
// does anything whose exposure without authentication would matter.
func handlerBodyIsSensitive(lines []string, start int, ext string) bool {
	re, ok := sensitiveOps[ext]
	if !ok {
		// An extension with no operation vocabulary defined gets the old
		// behaviour rather than silent suppression: failing open here keeps a
		// language's coverage from disappearing without anyone noticing.
		return true
	}
	end := start + 1 + maxHandlerBodyLines
	if end > len(lines) {
		end = len(lines)
	}
	for i := start + 1; i < end; i++ {
		line := lines[i]
		if funcStartRE.MatchString(line) {
			break
		}
		if strings.HasPrefix(strings.TrimSpace(line), "//") || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue // prose describing an operation is not the operation
		}
		if re.MatchString(line) {
			return true
		}
	}
	return false
}
