//go:build conformance

package conformance

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoInternalImports enforces the one structural rule of this suite: it
// validates the provider through HTTP only and must not share code with it.
func TestNoInternalImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(path, "github.com/tendant/idpico/") {
				t.Errorf("%s imports %s: the conformance suite must not import idpico packages", f, path)
			}
		}
	}
}
