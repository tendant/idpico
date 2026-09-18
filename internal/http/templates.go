package http

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

// Templates renders the server-side HTML pages. Every page is parsed together
// with the shared layout so it only has to define "title" and "content".
type Templates struct {
	pages  map[string]*template.Template
	logger *slog.Logger
}

// LoadTemplates parses the embedded templates. It panics on a malformed
// template since that is a build defect, not a runtime condition.
func LoadTemplates(logger *slog.Logger) *Templates {
	t := &Templates{pages: map[string]*template.Template{}, logger: logger}
	if err := t.loadDir(templateFS, "templates", "layout.html"); err != nil {
		panic(err)
	}
	return t
}

// loadDir parses every page under dir (except the layout) against layout.
func (t *Templates) loadDir(fsys fs.FS, dir, layout string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}
	layoutPath := path.Join(dir, layout)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == layout || !strings.HasSuffix(name, ".html") {
			continue
		}
		tmpl, err := template.New(name).ParseFS(fsys, layoutPath, path.Join(dir, name))
		if err != nil {
			return fmt.Errorf("parse template %s: %w", name, err)
		}
		t.pages[strings.TrimSuffix(name, ".html")] = tmpl
	}
	return nil
}

// Render writes the named page with data and the given status code. The page
// is rendered to a buffer first so a template error never produces a
// half-written response.
func (t *Templates) Render(w http.ResponseWriter, status int, name string, data any) {
	tmpl, ok := t.pages[name]
	if !ok {
		t.logger.Error("unknown template", "name", name)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		t.logger.Error("failed to render template", "name", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// errorPageData drives error.html.
type errorPageData struct {
	Title     string
	Message   string
	BackURL   string
	BackLabel string
}
