package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-git/go-git/v6/config"
)

func TestVerifyOptionsFromConfigNil(t *testing.T) {
	t.Parallel()
	opts, err := VerifyOptionsFromConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Empty(t, opts.SSHAllowedSigners)
}

func TestVerifyOptionsFromConfigAllowedSigners(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	allowedSigners := filepath.Join(dir, "allowed_signers")
	const line = "go-git-test@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+4+fTk/Jb/39eFDfS7f2V5JgPYsATQ3PxPkaEVH7CC\n"
	require.NoError(t, os.WriteFile(allowedSigners, []byte(line), 0o600))

	cfg := &config.Config{}
	cfg.GPG.SSH.AllowedSignersFile = allowedSigners

	opts, err := VerifyOptionsFromConfig(cfg)
	require.NoError(t, err)
	require.Len(t, opts.SSHAllowedSigners, 1)
	assert.Equal(t, []string{"go-git-test@example.com"}, opts.SSHAllowedSigners[0].Principals)
	assert.NotNil(t, opts.SSHAllowedSigners[0].Key)
}

func TestVerifyOptionsFromConfigMissingFile(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.GPG.SSH.AllowedSignersFile = filepath.Join(t.TempDir(), "does-not-exist")

	_, err := VerifyOptionsFromConfig(cfg)
	require.Error(t, err)
}
