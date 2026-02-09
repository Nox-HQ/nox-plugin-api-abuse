package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// abuseRule defines a single API abuse detection rule with compiled regex
// patterns keyed by file extension.
type abuseRule struct {
	ID         string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Message    string
	CWE        string
	Patterns   map[string][]*regexp.Regexp // extension -> compiled patterns
}

// Compiled regex patterns for each rule, grouped by language extension.
//
// API-ABUSE-001: Missing authentication check on handler.
// API-ABUSE-002: BOLA risk -- user ID from URL/query used in DB query without ownership check.
// API-ABUSE-003: Missing rate limiting on authentication endpoints.
// API-ABUSE-004: Mass assignment -- full request body bound to model without field filtering.
// API-ABUSE-005: Verbose error responses leaking internals.
var rules = []abuseRule{
	{
		ID:         "API-ABUSE-001",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceHigh,
		Message:    "Missing authentication check on handler",
		CWE:        "CWE-306",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`func\s+\w+\s*\(\s*w\s+http\.ResponseWriter\s*,\s*r\s+\*http\.Request\s*\)`),
				regexp.MustCompile(`(?i)http\.HandleFunc\s*\(\s*["']/(?!health|ready|alive)`),
			},
			".py": {
				regexp.MustCompile(`(?i)def\s+\w+\s*\(\s*request\s*[,)]`),
				regexp.MustCompile(`(?i)@app\.(?:route|get|post|put|delete)\s*\(`),
			},
			".js": {
				regexp.MustCompile(`(?i)(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]\/`),
				regexp.MustCompile(`(?i)exports\.\w+\s*=\s*(?:async\s+)?function\s*\(\s*req\s*,\s*res`),
			},
			".ts": {
				regexp.MustCompile(`(?i)(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]\/`),
				regexp.MustCompile(`(?i)exports\.\w+\s*=\s*(?:async\s+)?function\s*\(\s*req\s*,\s*res`),
			},
		},
	},
	{
		ID:         "API-ABUSE-002",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceMedium,
		Message:    "BOLA risk: user ID from request used directly in database query without ownership check",
		CWE:        "CWE-639",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)(?:Param|Query|FormValue|Vars)\s*\(\s*["'](?:user_?id|userId|id)["']\)`),
				regexp.MustCompile(`(?i)(?:Find|Get|Delete|Update).*(?:Param|Query|FormValue|Vars)\s*\(`),
			},
			".py": {
				regexp.MustCompile(`(?i)request\.(?:args|form|json|data)\s*(?:\[|\.get\s*\()\s*["'](?:user_?id|id)["']`),
				regexp.MustCompile(`(?i)(?:filter|get|delete)\s*\(.*(?:user_?id|id)\s*=\s*request\.`),
			},
			".js": {
				regexp.MustCompile(`(?i)req\.(?:params|query|body)\s*\.\s*(?:user_?[Ii]d|id)`),
				regexp.MustCompile(`(?i)(?:findById|findOne|deleteOne|updateOne)\s*\(\s*req\.(?:params|query|body)\.(?:id|user_?[Ii]d)`),
			},
			".ts": {
				regexp.MustCompile(`(?i)req\.(?:params|query|body)\s*\.\s*(?:user_?[Ii]d|id)`),
				regexp.MustCompile(`(?i)(?:findById|findOne|deleteOne|updateOne)\s*\(\s*req\.(?:params|query|body)\.(?:id|user_?[Ii]d)`),
			},
		},
	},
	{
		ID:         "API-ABUSE-003",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Missing rate limiting on authentication endpoint",
		CWE:        "CWE-307",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)HandleFunc\s*\(\s*["'].*(?:/login|/signin|/auth|/password|/reset|/register|/signup)["']`),
				regexp.MustCompile(`(?i)\.(?:POST|PUT)\s*\(\s*["'].*(?:/login|/signin|/auth|/password|/reset|/register|/signup)["']`),
			},
			".py": {
				regexp.MustCompile(`(?i)@app\.(?:route|post)\s*\(\s*["'].*(?:/login|/signin|/auth|/password|/reset|/register|/signup)["']`),
				regexp.MustCompile(`(?i)path\s*\(\s*["'].*(?:login|signin|auth|password|reset|register|signup)["']`),
			},
			".js": {
				regexp.MustCompile(`(?i)(?:app|router)\.(?:post|put)\s*\(\s*['"].*(?:/login|/signin|/auth|/password|/reset|/register|/signup)['"]`),
			},
			".ts": {
				regexp.MustCompile(`(?i)(?:app|router)\.(?:post|put)\s*\(\s*['"].*(?:/login|/signin|/auth|/password|/reset|/register|/signup)['"]`),
			},
		},
	},
	{
		ID:         "API-ABUSE-004",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Mass assignment vulnerability: full request body bound to model without field filtering",
		CWE:        "CWE-915",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`json\.NewDecoder\s*\(\s*r\.Body\s*\)\.Decode\s*\(&`),
				regexp.MustCompile(`(?i)c\.(?:Bind|ShouldBind|BindJSON|ShouldBindJSON)\s*\(&`),
			},
			".py": {
				regexp.MustCompile(`(?i)\*\*request\.(?:json|data|POST)`),
				regexp.MustCompile(`(?i)(?:serializer|form)\s*=\s*\w+Serializer\s*\(\s*data\s*=\s*request\.(?:data|json|POST)`),
				regexp.MustCompile(`(?i)Model\.objects\.create\s*\(\s*\*\*request`),
			},
			".js": {
				regexp.MustCompile(`(?i)(?:create|update|insert)\s*\(\s*req\.body\s*\)`),
				regexp.MustCompile(`(?i)Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)`),
				regexp.MustCompile(`(?i)new\s+\w+\s*\(\s*req\.body\s*\)`),
			},
			".ts": {
				regexp.MustCompile(`(?i)(?:create|update|insert)\s*\(\s*req\.body\s*\)`),
				regexp.MustCompile(`(?i)Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)`),
				regexp.MustCompile(`(?i)new\s+\w+\s*\(\s*req\.body\s*\)`),
			},
		},
	},
	{
		ID:         "API-ABUSE-005",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceHigh,
		Message:    "Verbose error response: internal details leaked to client",
		CWE:        "CWE-209",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)http\.Error\s*\(\s*w\s*,\s*(?:err\.Error\(\)|fmt\.Sprintf.*err)`),
				regexp.MustCompile(`(?i)json\..*(?:err\.Error\(\)|\.Stack)`),
				regexp.MustCompile(`(?i)w\.Write\s*\(.*err\.Error\(\)`),
			},
			".py": {
				regexp.MustCompile(`(?i)return\s+(?:HttpResponse|JsonResponse)\s*\(.*(?:traceback|str\(e\)|repr\(e\))`),
				regexp.MustCompile(`(?i)(?:jsonify|json\.dumps)\s*\(.*(?:traceback|str\(e\)|repr\(e\))`),
				regexp.MustCompile(`(?i)response\.data\s*=.*(?:traceback|str\(e\))`),
			},
			".js": {
				regexp.MustCompile(`(?i)res\.(?:json|send|status)\s*\(.*(?:err\.stack|err\.message|error\.stack|error\.message)`),
				regexp.MustCompile(`(?i)(?:message|error)\s*:\s*(?:err|error)\.(?:stack|message)`),
			},
			".ts": {
				regexp.MustCompile(`(?i)res\.(?:json|send|status)\s*\(.*(?:err\.stack|err\.message|error\.stack|error\.message)`),
				regexp.MustCompile(`(?i)(?:message|error)\s*:\s*(?:err|error)\.(?:stack|message)`),
			},
		},
	},
}

// mitigationCheck allows suppressing findings when a mitigation pattern is
// present in the same file.
type mitigationCheck struct {
	RuleID  string
	Pattern *regexp.Regexp
}

// mitigations are file-wide patterns that indicate proper security controls.
var mitigations = []mitigationCheck{
	{"API-ABUSE-001", regexp.MustCompile(`(?i)(?:authMiddleware|requireAuth|isAuthenticated|jwt\.verify|passport\.authenticate|@login_required|@requires_auth|@permission_required)`)},
	{"API-ABUSE-003", regexp.MustCompile(`(?i)(?:rate_limit|ratelimit|throttle|limiter|RateLimiter|slowDown)`)},
}

// supportedExtensions lists file extensions that the scanner processes.
var supportedExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/api-abuse", version).
		Capability("api-abuse", "Detect API authorization and abuse vulnerabilities in server code").
		Tool("scan", "Scan source files for missing auth checks, BOLA risks, mass assignment, and verbose errors", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskActive), sdk.WithNeedsConfirmation()).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !supportedExtensions[ext] {
			return nil
		}

		return scanFile(ctx, resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

// scanFile reads a file and checks each line against all API abuse rules.
// Mitigations found anywhere in the file suppress associated findings.
func scanFile(_ context.Context, resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	fullContent := strings.Join(lines, "\n")

	// Determine which rules have mitigations present in this file.
	mitigated := make(map[string]bool)
	for _, m := range mitigations {
		if m.Pattern.MatchString(fullContent) {
			mitigated[m.RuleID] = true
		}
	}

	for lineNum, line := range lines {
		for i := range rules {
			rule := &rules[i]
			patterns, ok := rule.Patterns[ext]
			if !ok {
				continue
			}

			matched := false
			for _, pattern := range patterns {
				if pattern.MatchString(line) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			if mitigated[rule.ID] {
				continue
			}

			resp.Finding(
				rule.ID,
				rule.Severity,
				rule.Confidence,
				fmt.Sprintf("%s: %s", rule.Message, strings.TrimSpace(line)),
			).
				At(filePath, lineNum+1, lineNum+1).
				WithMetadata("cwe", rule.CWE).
				WithMetadata("language", extToLanguage(ext)).
				Done()
		}
	}

	return nil
}

// extToLanguage maps file extensions to human-readable language names.
func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "unknown"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-api-abuse: %v\n", err)
		os.Exit(1)
	}
}
