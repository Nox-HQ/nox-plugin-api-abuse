package main

import (
	"strings"
	"testing"
)

// Shapes taken from nox's precision corpus, where API-ABUSE-001 fired on 17 of
// 17 handlers — every clean fixture and every vulnerable one — discriminating
// nothing.
func TestHandlerBodyIsSensitive(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			// tp_cmdinjection.go: shells out with a request value.
			name: "shells out",
			body: "func h(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"report\")\n\tout, _ := exec.Command(\"sh\", \"-c\", name).Output()\n\t_, _ = w.Write(out)\n}",
			want: true,
		},
		{
			// clean_html_autoescape.go: reads params, renders through a template.
			// Reading a parameter is not, by itself, worth an auth finding.
			name: "renders a template only",
			body: "func h(w http.ResponseWriter, r *http.Request) {\n\tdata := struct{ Name string }{Name: r.URL.Query().Get(\"name\")}\n\t_ = page.Execute(w, data)\n}",
			want: false,
		},
		{
			// The bug that made the first attempt useless: `.Query(` matched
			// r.URL.Query(), so "touches a database" was true for every handler
			// that read a query parameter.
			name: "url query is not a database query",
			body: "func h(w http.ResponseWriter, r *http.Request) {\n\tv := r.URL.Query().Get(\"x\")\n\t_, _ = w.Write([]byte(v))\n}",
			want: false,
		},
		{
			name: "real database access",
			body: "func h(w http.ResponseWriter, r *http.Request) {\n\trows, _ := db.Query(\"SELECT 1\")\n\t_ = rows\n}",
			want: true,
		},
		{
			name: "reads a file",
			body: "func h(w http.ResponseWriter, r *http.Request) {\n\tb, _ := os.ReadFile(r.URL.Query().Get(\"p\"))\n\t_, _ = w.Write(b)\n}",
			want: true,
		},
		{
			// Prose describing an operation is not the operation.
			name: "operation only mentioned in a comment",
			body: "func h(w http.ResponseWriter, r *http.Request) {\n\t// previously called exec.Command here\n\t_, _ = w.Write(nil)\n}",
			want: false,
		},
		{
			// The scan must stop at the next declaration, or every handler
			// inherits the sensitivity of whatever follows it.
			name: "does not run past the next function",
			body: "func h(w http.ResponseWriter, r *http.Request) {\n\t_, _ = w.Write(nil)\n}\n\nfunc other() {\n\texec.Command(\"x\")\n}",
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.body, "\n")
			if got := handlerBodyIsSensitive(lines, 0, ".go"); got != tc.want {
				t.Errorf("handlerBodyIsSensitive = %v, want %v\n%s", got, tc.want, tc.body)
			}
		})
	}
}

// An extension with no vocabulary defined must keep the old behaviour rather
// than silently reporting nothing.
func TestHandlerBodyIsSensitive_UnknownExtensionFailsOpen(t *testing.T) {
	if !handlerBodyIsSensitive([]string{"func h() {", "}"}, 0, ".rb") {
		t.Error("an unmodelled language lost its coverage silently")
	}
}
