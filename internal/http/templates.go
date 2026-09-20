package http

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed templates/*.html templates/admin/*.html templates/wide/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// FaviconHandler answers /favicon.ico, which browsers request from the site
// root regardless of any <link rel="icon"> on the page.
func FaviconHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/favicon.ico"
		StaticHandler().ServeHTTP(w, r)
	})
}

// staticVersions maps each embedded static file to a short content hash, so
// templates can link it as /static/<name>?v=<hash>: the URL changes whenever
// the file does, and a new binary can never be paired with a stylesheet a
// browser cached from the previous one.
var staticVersions = func() map[string]string {
	v := map[string]string{}
	if err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		v[strings.TrimPrefix(p, "static/")] = hex.EncodeToString(sum[:4])
		return nil
	}); err != nil {
		panic(err)
	}
	return v
}()

// assetURL returns the versioned URL for an embedded static file.
func assetURL(name string) string {
	if v, ok := staticVersions[name]; ok {
		return "/static/" + name + "?v=" + v
	}
	return "/static/" + name
}

// StaticHandler serves the embedded stylesheet and icons under /static/.
// Versioned URLs (?v=<hash>, as the templates emit) may be cached
// indefinitely; bare ones get an hour so /favicon.ico still picks up changes.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		files.ServeHTTP(w, r)
	})
}

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
	if err := t.loadDir(templateFS, "templates", "layout.html", ""); err != nil {
		panic(err)
	}
	if err := t.loadDir(templateFS, "templates/admin", "layout.html", "admin/"); err != nil {
		panic(err)
	}
	if err := t.loadDir(templateFS, "templates/wide", "layout.html", "wide/"); err != nil {
		panic(err)
	}
	return t
}

// templateFuncs are available to every page.
var templateFuncs = template.FuncMap{
	"join":  strings.Join,
	"asset": assetURL,
	"ttl":   ttlForm,
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
}

// loadDir parses every page under dir (except the layout) against layout and
// registers it under prefix+name.
func (t *Templates) loadDir(fsys fs.FS, dir, layout, prefix string) error {
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
		tmpl, err := template.New(name).Funcs(templateFuncs).ParseFS(fsys, layoutPath, path.Join(dir, name))
		if err != nil {
			return fmt.Errorf("parse template %s: %w", name, err)
		}
		t.pages[prefix+strings.TrimSuffix(name, ".html")] = tmpl
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

// setupPageData drives setup.html, shown on / while no user exists.
type setupPageData struct {
	Email string // example address used in the snippets
}

// errorPageData drives error.html.
type errorPageData struct {
	Title     string
	Message   string
	BackURL   string
	BackLabel string
}
