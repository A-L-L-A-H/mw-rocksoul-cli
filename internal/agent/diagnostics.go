package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	diagnosticsTimeout   = 60 * time.Second
	diagnosticsMaxOutput = 8 * 1024
)

// DiagnosticsResult is the outcome of a post-edit check.
type DiagnosticsResult struct {
	Command  string
	Output   string
	OK       bool
	TimedOut bool
}

// DiagnosticsCommand maps an edited file to its fast checker; ok is false when none applies.
func DiagnosticsCommand(editedFile string) (name string, args []string, ok bool) {
	switch strings.ToLower(filepath.Ext(editedFile)) {
	case ".go":
		return "go", []string{"vet", "./..."}, true
	case ".ts", ".tsx":
		return "tsc", []string{"--noEmit"}, true
	case ".rs":
		return "cargo", []string{"check", "--message-format=short"}, true
	}
	return "", nil, false
}

type limitedBuffer struct {
	buf bytes.Buffer
}

func (l *limitedBuffer) Write(chunk []byte) (int, error) {
	if room := diagnosticsMaxOutput - l.buf.Len(); room > 0 {
		if len(chunk) > room {
			l.buf.Write(chunk[:room])
		} else {
			l.buf.Write(chunk)
		}
	}
	return len(chunk), nil
}

// RunDiagnostics runs the checker for editedFile inside workDir with bounded time and output.
func RunDiagnostics(ctx context.Context, workDir, editedFile string) (DiagnosticsResult, error) {
	name, args, ok := DiagnosticsCommand(editedFile)
	if !ok {
		return DiagnosticsResult{}, fmt.Errorf("no diagnostics for %q", editedFile)
	}
	runCtx, cancel := context.WithTimeout(ctx, diagnosticsTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Dir = workDir
	var sink limitedBuffer
	cmd.Stdout = &sink
	cmd.Stderr = &sink
	runErr := cmd.Run()
	result := DiagnosticsResult{
		Command:  name + " " + strings.Join(args, " "),
		Output:   sink.buf.String(),
		OK:       runErr == nil,
		TimedOut: runCtx.Err() == context.DeadlineExceeded,
	}
	return result, nil
}
