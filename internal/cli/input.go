package cli

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keshon/proxycheck/pkg/check"
)

// LoadProxies reads proxy lines from the given files and/or directories, or from
// stdin when the list is empty or contains "-". A directory is expanded to every
// regular file it contains, recursively. Blank lines and lines starting with #
// are skipped. Parse errors are collected and returned alongside the good
// proxies so one malformed line doesn't abort a big list. Duplicates (across all
// sources) are removed.
func LoadProxies(paths []string) ([]check.Proxy, []error, error) {
	if len(paths) == 0 {
		paths = []string{"-"}
	}

	files, err := expandPaths(paths)
	if err != nil {
		return nil, nil, err
	}

	var proxies []check.Proxy
	var parseErrs []error
	seen := make(map[string]struct{})

	for _, path := range files {
		r, closeFn, err := open(path)
		if err != nil {
			return nil, nil, err
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Tolerate lists that annotate each proxy, e.g. "ip:port # 2.5s" or
			// "ip:port latency": the proxy is always the first whitespace token.
			line = strings.Fields(line)[0]
			p, err := check.ParseProxy(line)
			if err != nil {
				parseErrs = append(parseErrs, err)
				continue
			}
			key := p.String()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			proxies = append(proxies, p)
		}
		closeFn()
		if err := sc.Err(); err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	return proxies, parseErrs, nil
}

// expandPaths turns a mix of files, directories, and "-" (stdin) into a flat,
// ordered file list. Directories are walked recursively; within a directory
// files are visited in lexical order for deterministic output.
func expandPaths(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		if p == "-" {
			out = append(out, p)
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("access %s: %w", p, err)
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}

		var dirFiles []string
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				dirFiles = append(dirFiles, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", p, err)
		}
		sort.Strings(dirFiles)
		out = append(out, dirFiles...)
	}
	return out, nil
}

func open(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}
