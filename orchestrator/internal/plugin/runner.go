package plugin

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExecRunner is the production Runner. It executes tools with an explicit argv
// slice and never invokes a shell, so tool parameters derived from scan input
// can never become shell metacharacters.
type ExecRunner struct {
	BinDir string // searched before $PATH; may be empty
}

func (e ExecRunner) Look(binary string) (string, error) {
	if strings.ContainsAny(binary, "/\\") {
		return "", errors.New("binary name must not contain a path separator")
	}
	if e.BinDir != "" {
		p := filepath.Join(e.BinDir, binary)
		if fi, err := exec.LookPath(p); err == nil {
			return fi, nil
		}
	}
	return exec.LookPath(binary)
}

func (e ExecRunner) Exec(ctx context.Context, argv []string) (string, int, error) {
	if len(argv) == 0 {
		return "", -1, errors.New("empty argv")
	}
	// argv[0] may already be an absolute path returned by an earlier Look call;
	// otherwise resolve it. A relative path with a separator is rejected.
	path := argv[0]
	if !filepath.IsAbs(path) {
		var err error
		if path, err = e.Look(argv[0]); err != nil {
			return "", -1, err
		}
	}
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	out := buf.String()
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return out, ee.ExitCode(), nil
		}
		return out, -1, runErr
	}
	return out, 0, nil
}
