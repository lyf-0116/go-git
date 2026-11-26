package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const untrustedConfigInput = `
[url "ssh://evil.example/"]
	insteadOf = https://github.com/
	pushInsteadOf = git://github.com/
[credential "https://evil.example"]
	helper = evil-helper
	username = victim
[http]
	proxy = http://proxy.example:8080
[http "https://other.example"]
	extraHeader = X-Token: leaked
[remote "origin"]
	url = https://github.com/go-git/go-git.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[core]
	bare = false
`

func untrustedTestConfig(t *testing.T) *Config {
	t.Helper()

	cfg := NewConfig()
	require.NoError(t, cfg.Unmarshal([]byte(untrustedConfigInput)))
	return cfg
}

func TestSanitizeUntrustedStripsAllSensitiveDirectives(t *testing.T) {
	t.Parallel()

	cfg := untrustedTestConfig(t)

	// The rewrite is applied while unmarshalling.
	origin := cfg.Remotes["origin"]
	require.NotNil(t, origin)
	require.Equal(t, "ssh://evil.example/go-git/go-git.git", origin.URLs[0])

	rejected := SanitizeUntrusted(cfg, UntrustedConfigOptions{})

	assert.Empty(t, cfg.URLs)
	assert.False(t, cfg.Raw.HasSection(urlSectionRewrite))
	assert.False(t, cfg.Raw.HasSection(credentialSection))
	assert.False(t, cfg.Raw.HasSection(httpSection))

	// Remote URLs are restored to their literal, pre-rewrite values.
	assert.Equal(t, "https://github.com/go-git/go-git.git", origin.URLs[0])
	assert.False(t, origin.insteadOfRulesApplied)

	// Non-sensitive directives survive.
	assert.True(t, cfg.Raw.HasSection(coreSection))
	assert.Contains(t, cfg.Remotes, "origin")

	keys := make([]string, 0, len(rejected))
	for _, r := range rejected {
		keys = append(keys, r.String())
	}
	assert.Contains(t, keys, "url.ssh://evil.example/.insteadOf: url rewrite rules are disabled for untrusted repositories")
	assert.Contains(t, keys, "url.ssh://evil.example/.pushInsteadOf: url rewrite rules are disabled for untrusted repositories")
	assert.Contains(t, keys, "credential.https://evil.example.helper: credential directives are disabled for untrusted repositories")
	assert.Contains(t, keys, "http.proxy: http directives are disabled for untrusted repositories")
	assert.Contains(t, keys, "http.https://other.example.extraHeader: http directives are disabled for untrusted repositories")
}

func TestSanitizeUntrustedGranularAllows(t *testing.T) {
	t.Parallel()

	t.Run("allow url rewrites", func(t *testing.T) {
		cfg := untrustedTestConfig(t)
		rejected := SanitizeUntrusted(cfg, UntrustedConfigOptions{AllowURLRewrites: true})

		assert.Len(t, cfg.URLs, 1)
		assert.True(t, cfg.Raw.HasSection(urlSectionRewrite))
		assert.Equal(t, "ssh://evil.example/go-git/go-git.git", cfg.Remotes["origin"].URLs[0])
		assert.False(t, cfg.Raw.HasSection(credentialSection))
		assert.False(t, cfg.Raw.HasSection(httpSection))

		for _, r := range rejected {
			assert.NotEqual(t, urlSectionRewrite, r.Section)
		}
	})

	t.Run("allow credentials", func(t *testing.T) {
		cfg := untrustedTestConfig(t)
		rejected := SanitizeUntrusted(cfg, UntrustedConfigOptions{AllowCredentials: true})

		assert.True(t, cfg.Raw.HasSection(credentialSection))
		assert.False(t, cfg.Raw.HasSection(urlSectionRewrite))
		assert.False(t, cfg.Raw.HasSection(httpSection))
		for _, r := range rejected {
			assert.NotEqual(t, credentialSection, r.Section)
		}
	})

	t.Run("allow http", func(t *testing.T) {
		cfg := untrustedTestConfig(t)
		rejected := SanitizeUntrusted(cfg, UntrustedConfigOptions{AllowHTTP: true})

		assert.True(t, cfg.Raw.HasSection(httpSection))
		assert.False(t, cfg.Raw.HasSection(urlSectionRewrite))
		assert.False(t, cfg.Raw.HasSection(credentialSection))
		for _, r := range rejected {
			assert.NotEqual(t, httpSection, r.Section)
		}
	})

	t.Run("allow everything keeps config intact", func(t *testing.T) {
		cfg := untrustedTestConfig(t)
		rejected := SanitizeUntrusted(cfg, UntrustedConfigOptions{
			AllowURLRewrites: true,
			AllowCredentials: true,
			AllowHTTP:        true,
		})

		assert.Empty(t, rejected)
		assert.Len(t, cfg.URLs, 1)
		assert.True(t, cfg.Raw.HasSection(credentialSection))
		assert.True(t, cfg.Raw.HasSection(httpSection))
	})
}

func TestSanitizeUntrustedReportsNothingForCleanConfig(t *testing.T) {
	t.Parallel()

	cfg := NewConfig()
	require.NoError(t, cfg.Unmarshal([]byte(`
[remote "origin"]
	url = https://example.com/repo.git
`)))

	assert.Empty(t, SanitizeUntrusted(cfg, UntrustedConfigOptions{}))
	assert.Equal(t, "https://example.com/repo.git", cfg.Remotes["origin"].URLs[0])
}

func TestSanitizeUntrustedNilConfig(t *testing.T) {
	t.Parallel()

	assert.NotPanics(t, func() {
		assert.Nil(t, SanitizeUntrusted(nil, UntrustedConfigOptions{}))
	})
}

func TestRejectedConfigString(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"http.proxy: blocked",
		(RejectedConfig{Section: "http", Key: "proxy", Reason: "blocked"}).String(),
	)
	assert.Equal(t,
		"url.https://example.com/.insteadOf: blocked",
		(RejectedConfig{
			Section:    "url",
			Subsection: "https://example.com/",
			Key:        "insteadOf",
			Reason:     "blocked",
		}).String(),
	)
}
