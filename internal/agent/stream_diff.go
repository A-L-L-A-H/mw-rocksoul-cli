package agent

import (
	"fmt"
	"strings"
)

// StreamDiffLineType identifies additions, deletions, context, or metadata.
type StreamDiffLineType string

const (
	DiffLineContext StreamDiffLineType = "context"
	DiffLineAdd     StreamDiffLineType = "add"
	DiffLineDelete  StreamDiffLineType = "delete"
	DiffLineHunk    StreamDiffLineType = "hunk"
	DiffLineHeader  StreamDiffLineType = "header"
)

// StreamDiffLine represents a parsed unified diff line for streaming UI rendering.
type StreamDiffLine struct {
	Type    StreamDiffLineType `json:"type"`
	Text    string             `json:"text"`
	OldLine int                `json:"oldLine,omitempty"`
	NewLine int                `json:"newLine,omitempty"`
}

// StreamDiffParser statefully parses chunks of unified diff output.
type StreamDiffParser struct {
	oldLineNum int
	newLineNum int
	buffer     string
}

// NewStreamDiffParser initializes a new streaming diff parser.
func NewStreamDiffParser() *StreamDiffParser {
	return &StreamDiffParser{}
}

// ParseChunk processes an incoming raw diff chunk and returns complete parsed diff lines.
func (p *StreamDiffParser) ParseChunk(chunk string) []StreamDiffLine {
	p.buffer += strings.ReplaceAll(chunk, "\r\n", "\n")
	var result []StreamDiffLine

	for {
		idx := strings.IndexByte(p.buffer, '\n')
		if idx == -1 {
			break
		}
		rawLine := p.buffer[:idx]
		p.buffer = p.buffer[idx+1:]
		if line, ok := p.processLine(rawLine); ok {
			result = append(result, line)
		}
	}
	return result
}

// Flush emits any remaining buffered line.
func (p *StreamDiffParser) Flush() []StreamDiffLine {
	if p.buffer == "" {
		return nil
	}
	raw := p.buffer
	p.buffer = ""
	if line, ok := p.processLine(raw); ok {
		return []StreamDiffLine{line}
	}
	return nil
}

func (p *StreamDiffParser) processLine(raw string) (StreamDiffLine, bool) {
	if strings.HasPrefix(raw, "---") || strings.HasPrefix(raw, "+++") {
		return StreamDiffLine{Type: DiffLineHeader, Text: raw}, true
	}
	if strings.HasPrefix(raw, "@@") {
		var oldStart, newStart int
		_, _ = fmt.Sscanf(raw, "@@ -%d,%*d +%d,%*d @@", &oldStart, &newStart)
		if oldStart == 0 {
			_, _ = fmt.Sscanf(raw, "@@ -%d +%d @@", &oldStart, &newStart)
		}
		p.oldLineNum = oldStart
		p.newLineNum = newStart
		return StreamDiffLine{Type: DiffLineHunk, Text: raw}, true
	}
	if strings.HasPrefix(raw, "+") {
		ln := p.newLineNum
		if p.newLineNum > 0 {
			p.newLineNum++
		}
		return StreamDiffLine{Type: DiffLineAdd, Text: strings.TrimPrefix(raw, "+"), NewLine: ln}, true
	}
	if strings.HasPrefix(raw, "-") {
		ln := p.oldLineNum
		if p.oldLineNum > 0 {
			p.oldLineNum++
		}
		return StreamDiffLine{Type: DiffLineDelete, Text: strings.TrimPrefix(raw, "-"), OldLine: ln}, true
	}
	if strings.HasPrefix(raw, " ") {
		ol := p.oldLineNum
		nl := p.newLineNum
		if p.oldLineNum > 0 {
			p.oldLineNum++
		}
		if p.newLineNum > 0 {
			p.newLineNum++
		}
		return StreamDiffLine{Type: DiffLineContext, Text: strings.TrimPrefix(raw, " "), OldLine: ol, NewLine: nl}, true
	}
	return StreamDiffLine{Type: DiffLineHeader, Text: raw}, true
}
