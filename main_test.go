package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackDynamicRuntime)
}

func TestAPIABUSE001_MissingAuth(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "API-ABUSE-001")
	if len(found) == 0 {
		t.Fatal("expected at least one API-ABUSE-001 (Missing Authentication) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("API-ABUSE-001 severity should be HIGH, got %v", f.GetSeverity())
		}
		if f.GetLocation() == nil || f.GetLocation().GetStartLine() == 0 {
			t.Error("finding must include a location with non-zero start line")
		}
		if f.GetMetadata()["cwe"] != "CWE-306" {
			t.Errorf("expected CWE-306, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestAPIABUSE002_BOLA(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "API-ABUSE-002")
	if len(found) == 0 {
		t.Fatal("expected at least one API-ABUSE-002 (BOLA) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["cwe"] != "CWE-639" {
			t.Errorf("expected CWE-639, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestAPIABUSE003_MissingRateLimitAuth(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "API-ABUSE-003")
	if len(found) == 0 {
		t.Fatal("expected at least one API-ABUSE-003 (Missing Rate Limit on Auth) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("API-ABUSE-003 severity should be MEDIUM, got %v", f.GetSeverity())
		}
	}
}

func TestAPIABUSE004_MassAssignment(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "API-ABUSE-004")
	if len(found) == 0 {
		t.Fatal("expected at least one API-ABUSE-004 (Mass Assignment) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["cwe"] != "CWE-915" {
			t.Errorf("expected CWE-915, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestAPIABUSE005_VerboseErrors(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "API-ABUSE-005")
	if len(found) == 0 {
		t.Fatal("expected at least one API-ABUSE-005 (Verbose Error) finding")
	}

	for _, f := range found {
		if f.GetConfidence() != sdk.ConfidenceHigh {
			t.Errorf("API-ABUSE-005 confidence should be HIGH, got %v", f.GetConfidence())
		}
		if f.GetMetadata()["cwe"] != "CWE-209" {
			t.Errorf("expected CWE-209, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
