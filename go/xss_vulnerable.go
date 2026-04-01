package main

import (
	"fmt"
	"html/template"
	"net/http"
	_ "text/template"
)

// Matches: go-template-html (existing)
func vulnerableTemplateHTML(userInput string) template.HTML {
	return template.HTML(userInput)
}

// Matches: go-text-template-unescaped (pattern-regex matches import)
// The text/template import above triggers this rule

// Matches: go-fmt-fprintf-http
func vulnerableFprintf(w http.ResponseWriter, userInput string) {
	fmt.Fprintf(w, userInput)
}

// Safe: use html/template auto-escaping
func safeTemplate(w http.ResponseWriter, data interface{}) {
	tmpl := template.Must(template.New("page").Parse("<p>{{.}}</p>"))
	tmpl.Execute(w, data)
}
