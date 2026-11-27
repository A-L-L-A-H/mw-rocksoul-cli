package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var atMentionRegex = regexp.MustCompile(`@([\w\-./\\]+)`)

// AtMention represents an extracted @path mention in prompt text.
type AtMention struct {
	RawPath      string `json:"rawPath"`
	ResolvedPath string `json:"resolvedPath"`
	Exists       bool   `json:"exists"`
	IsDir        bool   `json:"isDir"`
	Content      string `json:"content,omitempty"`
}

// ParseAtMentions extracts @path references from a user prompt.
func ParseAtMentions(text string) []string {
	matches := atMentionRegex.FindAllStringSubmatch(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		if len(m) > 1 {
			target := strings.TrimRight(m[1], `.,;:!?)"'`)
			if target != "" && !seen[target] {
				seen[target] = true
				result = append(result, target)
			}
		}
	}
	return result
}

// ResolveAtMentions resolves parsed mentions against the workspace and embeds file contents.
func ResolveAtMentions(ctx context.Context, workDir string, prompt string) (string, []AtMention, error) {
	paths := ParseAtMentions(prompt)
	if len(paths) == 0 {
		return prompt, nil, nil
	}

	var mentions []AtMention
	var injected strings.Builder
	injected.WriteString(prompt)
	injected.WriteString("\n\n--- Mentioned Context ---\n")

	for _, p := range paths {
		targetPath := p
		if !filepath.IsAbs(targetPath) {
			targetPath = filepath.Join(workDir, targetPath)
		}
		targetPath = filepath.Clean(targetPath)

		rel, relErr := filepath.Rel(workDir, targetPath)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			// Outside workspace or invalid
			continue
		}

		info, err := os.Stat(targetPath)
		if err != nil {
			mentions = append(mentions, AtMention{RawPath: p, ResolvedPath: targetPath, Exists: false})
			continue
		}

		if info.IsDir() {
			mentions = append(mentions, AtMention{RawPath: p, ResolvedPath: targetPath, Exists: true, IsDir: true})
			fmt.Fprintf(&injected, "\nDirectory `@%s`:\n(directory exists)\n", p)
			continue
		}

		if info.Size() > 256*1024 { // max 256KB inline mention
			mentions = append(mentions, AtMention{RawPath: p, ResolvedPath: targetPath, Exists: true, Content: "(file too large to inline)"})
			fmt.Fprintf(&injected, "\nFile `@%s` (%d bytes - too large to inline):\n", p, info.Size())
			continue
		}

		data, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			continue
		}
		content := string(data)
		mentions = append(mentions, AtMention{RawPath: p, ResolvedPath: targetPath, Exists: true, Content: content})
		fmt.Fprintf(&injected, "\nFile `@%s`:\n```\n%s\n```\n", p, content)
	}

	return injected.String(), mentions, nil
}
