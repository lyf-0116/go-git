package git

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v6/utils/trace"
)

// ErrUnsafeRepository is returned by [PlainOpenWithOptions] when the
// repository directory is not owned by the current user and the path has
// not been explicitly marked as safe. It mirrors git's "detected dubious
// ownership" protection: configuration inside an untrusted repository can
// otherwise rewrite remote URLs or select credential helpers and redirect
// credentials to an attacker-controlled host.
var ErrUnsafeRepository = errors.New("dubious repository ownership: repository is not owned by the current user")

// safeDirectoryAll matches every path, equivalent to git's
// safe.directory = '*' setting.
const safeDirectoryAll = "*"

// isCurrentUserOwner reports whether the directory at path is owned by the
// user running the process. The supported result is false on platforms that
// have no file-ownership concept, in which case ownership checks are
// skipped.
//
// It is a package-level variable so tests can simulate a mismatching owner
// without creating a second system user.
var isCurrentUserOwner = checkIsCurrentUserOwner

// verifyDirectoryOwnership checks that every path in roots is owned by the
// current user. Both the git directory and the worktree root are checked,
// matching git which refuses a repository whose git dir or worktree is
// owned by somebody else.
//
// A path present in safeDirectories is trusted without an ownership check.
// The special "*" entry trusts every path. Platforms without an ownership
// concept are treated as always safe.
//
// It reports allowListed when access was granted only because one or more
// roots matched an explicit safe.directory entry rather than being owned by
// the current user; such repositories keep being opened but their local
// config is treated as untrusted.
func verifyDirectoryOwnership(roots []string, safeDirectories []string) (allowListed bool, err error) {
	if !hasOwnershipConcept() {
		return false, nil
	}

	for _, root := range roots {
		if root == "" {
			continue
		}

		owned, err := isCurrentUserOwner(root)
		if err != nil {
			return false, fmt.Errorf("check ownership of %q: %w", root, err)
		}
		if owned {
			// Directories owned by the current user are fully trusted even
			// when they also appear in the allow-list.
			continue
		}

		if !isSafeDirectory(root, safeDirectories) {
			trace.Security.Printf("unsafe repository %q: not owned by the current user", root)
			return false, fmt.Errorf("%w: %q", ErrUnsafeRepository, root)
		}

		allowListed = true
	}

	return allowListed, nil
}

// isSafeDirectory reports whether path matches an explicit safe.directory
// entry. Matching follows git: paths are compared after cleaning and
// resolving symlinks, and "*" matches everything.
func isSafeDirectory(path string, safeDirectories []string) bool {
	canonical := canonicalPath(path)

	for _, entry := range safeDirectories {
		if entry == safeDirectoryAll {
			return true
		}
		if entry == "" {
			continue
		}

		allowed := canonicalPath(entry)
		if canonical == allowed {
			return true
		}
		// safe.directory names the worktree root; the git directory is
		// normally the nested ".git" entry and must be covered by the same
		// trust decision.
		if canonical == filepath.Join(allowed, GitDirName) {
			return true
		}
	}

	return false
}

// canonicalPath returns an absolute, cleaned path with symlinks resolved
// where possible, so equivalent spellings of the same directory compare
// equal. It falls back to the cleaned absolute path when the path cannot be
// evaluated (for example because it no longer exists).
func canonicalPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return filepath.Clean(strings.TrimSuffix(path, string(os.PathSeparator)))
}
