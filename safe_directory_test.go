package git

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/utils/trace"
)

// writeSensitiveConfig writes a local config containing an insteadOf rewrite
// plus credential and http directives into an already initialised
// repository.
func writeSensitiveConfig(t *testing.T, dir string) {
	t.Helper()

	body := `
[url "ssh://evil.example/"]
	insteadOf = https://github.com/
[credential "https://evil.example"]
	helper = evil-helper
[http]
	proxy = http://proxy.example:8080
[remote "origin"]
	url = https://github.com/go-git/go-git.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`
	path := filepath.Join(dir, ".git", "config")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}

func TestPlainOpenRejectsForeignOwnedRepository(t *testing.T) {
	dir := t.TempDir()

	r, err := PlainInit(dir, false)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	prev := isCurrentUserOwner
	isCurrentUserOwner = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { isCurrentUserOwner = prev })

	_, err = PlainOpenWithOptions(dir, &PlainOpenOptions{})
	require.ErrorIs(t, err, ErrUnsafeRepository)
}

func TestPlainOpenSafeDirectoryBypassesOwnershipAndFiltersConfig(t *testing.T) {
	dir := t.TempDir()

	r, err := PlainInit(dir, false)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	writeSensitiveConfig(t, dir)

	prev := isCurrentUserOwner
	isCurrentUserOwner = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { isCurrentUserOwner = prev })

	var logs bytes.Buffer
	trace.SetLogger(log.New(&logs, "", 0))
	prevTarget := trace.Target(0)
	trace.SetTarget(trace.Security)
	t.Cleanup(func() {
		trace.SetLogger(log.New(os.Stderr, "", log.LstdFlags))
		trace.SetTarget(prevTarget)
	})

	opened, err := PlainOpenWithOptions(dir, &PlainOpenOptions{
		SafeDirectories: []string{dir},
	})
	require.NoError(t, err)
	defer func() { _ = opened.Close() }()

	cfg, err := opened.Config()
	require.NoError(t, err)

	assert.Empty(t, cfg.URLs)
	assert.Equal(t,
		"https://github.com/go-git/go-git.git",
		cfg.Remotes["origin"].URLs[0],
	)

	rejected := opened.RejectedConfig()
	assert.NotEmpty(t, rejected)

	sections := map[string]bool{}
	for _, item := range rejected {
		sections[item.Section] = true
	}
	assert.True(t, sections["url"])
	assert.True(t, sections["credential"])
	assert.True(t, sections["http"])

	assert.Contains(t, logs.String(), "untrusted repository config rejected")
}

func TestPlainOpenTrustAllFiltersConfig(t *testing.T) {
	dir := t.TempDir()

	r, err := PlainInit(dir, false)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	writeSensitiveConfig(t, dir)

	prev := isCurrentUserOwner
	isCurrentUserOwner = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { isCurrentUserOwner = prev })

	opened, err := PlainOpenWithOptions(dir, &PlainOpenOptions{TrustAll: true})
	require.NoError(t, err)
	defer func() { _ = opened.Close() }()

	cfg, err := opened.Config()
	require.NoError(t, err)
	assert.Empty(t, cfg.URLs)
	assert.NotEmpty(t, opened.RejectedConfig())
}

func TestPlainOpenSafeDirectoryGranularRewriteAllowance(t *testing.T) {
	dir := t.TempDir()

	r, err := PlainInit(dir, false)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	writeSensitiveConfig(t, dir)

	prev := isCurrentUserOwner
	isCurrentUserOwner = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { isCurrentUserOwner = prev })

	opened, err := PlainOpenWithOptions(dir, &PlainOpenOptions{
		SafeDirectories: []string{dir},
		UntrustedConfig: config.UntrustedConfigOptions{AllowURLRewrites: true},
	})
	require.NoError(t, err)
	defer func() { _ = opened.Close() }()

	cfg, err := opened.Config()
	require.NoError(t, err)

	assert.Len(t, cfg.URLs, 1)
	assert.Equal(t,
		"ssh://evil.example/go-git/go-git.git",
		cfg.Remotes["origin"].URLs[0],
	)

	for _, item := range opened.RejectedConfig() {
		assert.NotEqual(t, "url", item.Section)
	}
}

func TestPlainOpenOwnedRepositoryKeepsFullConfig(t *testing.T) {
	dir := t.TempDir()

	r, err := PlainInit(dir, false)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	writeSensitiveConfig(t, dir)

	prev := isCurrentUserOwner
	isCurrentUserOwner = func(string) (bool, error) { return true, nil }
	t.Cleanup(func() { isCurrentUserOwner = prev })

	opened, err := PlainOpenWithOptions(dir, &PlainOpenOptions{
		SafeDirectories: []string{dir},
	})
	require.NoError(t, err)
	defer func() { _ = opened.Close() }()

	cfg, err := opened.Config()
	require.NoError(t, err)
	assert.Len(t, cfg.URLs, 1)
	assert.Nil(t, opened.RejectedConfig())
}

func TestIsSafeDirectory(t *testing.T) {
	dir := t.TempDir()

	assert.True(t, isSafeDirectory(dir, []string{"*"}))
	assert.True(t, isSafeDirectory(dir, []string{dir}))
	assert.False(t, isSafeDirectory(dir, []string{filepath.Join(dir, "other")}))
	assert.False(t, isSafeDirectory(dir, nil))
}

func TestPlainOpenUntrustedRemoteUsesOriginalURL(t *testing.T) {
	dir := t.TempDir()

	r, err := PlainInit(dir, false)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	writeSensitiveConfig(t, dir)

	prev := isCurrentUserOwner
	isCurrentUserOwner = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { isCurrentUserOwner = prev })

	opened, err := PlainOpenWithOptions(dir, &PlainOpenOptions{TrustAll: true})
	require.NoError(t, err)
	defer func() { _ = opened.Close() }()

	remote, err := opened.Remote("origin")
	require.NoError(t, err)

	// The insteadOf rewrite that would redirect credentials to
	// evil.example is removed; the remote keeps its literal URL.
	assert.Equal(t,
		"https://github.com/go-git/go-git.git",
		remote.Config().URLs[0],
	)
}

func TestIsSafeDirectoryResolvesSymlink(t *testing.T) {
	dir := t.TempDir()

	r, err := PlainInit(dir, false)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(dir, link))

	gitDirViaLink := filepath.Join(link, GitDirName)

	// Allowing the real directory also covers the symlinked spelling,
	// because both canonicalise to the same path.
	assert.True(t, isSafeDirectory(gitDirViaLink, []string{dir}))
	assert.True(t, isSafeDirectory(gitDirViaLink, []string{link}))
}
