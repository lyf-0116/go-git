package object

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/go-git/go-git/v6/plumbing"
)

// The following fixtures were produced by real git 2.53 + OpenSSH
// ssh-keygen(1):
//
//	git -c gpg.format=ssh commit -S
//	git -c gpg.ssh.allowedSignersFile=... verify-commit/verify-tag
//
// They pin interoperability with the reference implementation, including the
// SSHSIG signed-data preamble and the SHA-256 fingerprint format.
const gitSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+4+fTk/Jb/39eFDfS7f2V5JgPYsATQ3PxPkaEVH7CC go-git-test@example.com"

const gitSSHFingerprint = "SHA256:06teDBEMUdoW1OgBERsy5OWTd90D01SqtvJ/GgJ7AJE"

const gitSSHCommitRaw = `tree 853694aae8816094a0d875fee7ea26278dbf5d0f
author Go Git Test <go-git-test@example.com> 1795731352 +0800
committer Go Git Test <go-git-test@example.com> 1795731352 +0800
gpgsig -----BEGIN SSH SIGNATURE-----
 U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgf7j59OT8lv/f14UN9Lt/ZXkmA9
 iwBNDc/E+RoRUfsIIAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
 AAAAQKuZaOrHURsz4AuOXD9t4/cti3J6yXGxf+BMWGkD51Imrbfj7drtviLRWcLS89+Pq8
 4u6sBNChqHhhXis6TBAQY=
 -----END SSH SIGNATURE-----

first signed commit
`

const gitSSHTagRaw = `object 34a891fb847ffad56e9f5177f28e9feb9af1992e
type commit
tag v1
tagger Go Git Test <go-git-test@example.com> 1795731352 +0800

signed tag v1
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgf7j59OT8lv/f14UN9Lt/ZXkmA9
iwBNDc/E+RoRUfsIIAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQBSk/eUViTtT0uJew4cuym+SJhGYo9Mc0n1XKzFiqmKaHAgxXrVUhHSf4G2AVYyqKI
JBTLE2vrMUOg5q2CJ9ogA=
-----END SSH SIGNATURE-----
`

func decodeRawObjectForTest(t *testing.T, raw string, typ plumbing.ObjectType) *plumbing.MemoryObject {
	t.Helper()
	obj := &plumbing.MemoryObject{}
	obj.SetType(typ)
	_, err := obj.Write([]byte(raw))
	require.NoError(t, err)
	return obj
}

func TestVerifySignatureSSHGitCommitFixture(t *testing.T) {
	t.Parallel()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(gitSSHPublicKey))
	require.NoError(t, err)

	var commit Commit
	require.NoError(t, commit.Decode(decodeRawObjectForTest(t, gitSSHCommitRaw, plumbing.CommitObject)))

	verification, err := commit.VerifySignature(&VerifyOptions{SSHKeys: []ssh.PublicKey{pub}})
	require.NoError(t, err)

	assert.Equal(t, SignatureTypeSSH, verification.Format)
	assert.Equal(t, SignatureTypeSSH, verification.Method)
	assert.Equal(t, gitSSHFingerprint, verification.Fingerprint)
	assert.Equal(t, gitSSHFingerprint, verification.Signer,
		"SSH signatures only identify the key fingerprint")
	assert.Equal(t, gitSSHFingerprint, ssh.FingerprintSHA256(verification.Details.(ssh.PublicKey)))
}

func TestVerifySignatureSSHGitTagFixture(t *testing.T) {
	t.Parallel()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(gitSSHPublicKey))
	require.NoError(t, err)

	var tag Tag
	require.NoError(t, tag.Decode(decodeRawObjectForTest(t, gitSSHTagRaw, plumbing.TagObject)))

	verification, err := tag.VerifySignature(&VerifyOptions{
		SSHAllowedSigners: []AllowedSigner{{
			Principals: []string{"go-git-test@example.com"},
			Key:        pub,
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, SignatureTypeSSH, verification.Format)
	assert.Equal(t, gitSSHFingerprint, verification.Signer)
	assert.Equal(t, []string{"go-git-test@example.com"}, verification.Principals)
}

func TestVerifySignatureSSHGeneratedKey(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	message := []byte("tree 0000000000000000000000000000000000000000\n\nhello\n")
	signature := generateSSHSignatureForTest(t, signer, sshSignatureNamespace, "sha512", message)

	fp := ssh.FingerprintSHA256(signer.PublicKey())

	t.Run("trusted key", func(t *testing.T) {
		t.Parallel()
		verification, err := VerifySignature(bytes.NewReader(message), signature,
			&VerifyOptions{SSHKeys: []ssh.PublicKey{signer.PublicKey()}})
		require.NoError(t, err)
		assert.Equal(t, fp, verification.Signer)
		assert.Equal(t, SignatureTypeSSH, verification.Format)
	})

	t.Run("sha256 hash", func(t *testing.T) {
		t.Parallel()
		sig256 := generateSSHSignatureForTest(t, signer, sshSignatureNamespace, "sha256", message)
		_, err := VerifySignature(bytes.NewReader(message), sig256,
			&VerifyOptions{SSHKeys: []ssh.PublicKey{signer.PublicKey()}})
		require.NoError(t, err)
	})

	t.Run("untrusted key", func(t *testing.T) {
		t.Parallel()
		_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		otherSigner, err := ssh.NewSignerFromKey(otherPriv)
		require.NoError(t, err)

		_, err = VerifySignature(bytes.NewReader(message), signature,
			&VerifyOptions{SSHKeys: []ssh.PublicKey{otherSigner.PublicKey()}})
		require.ErrorIs(t, err, ErrUntrustedSigner)
	})

	t.Run("tampered message", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySignature(bytes.NewReader(append(append([]byte{}, message...), 'x')), signature,
			&VerifyOptions{SSHKeys: []ssh.PublicKey{signer.PublicKey()}})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrUntrustedSigner)
	})

	t.Run("wrong namespace rejected", func(t *testing.T) {
		t.Parallel()
		fileSignature := generateSSHSignatureForTest(t, signer, "file", "sha512", message)
		_, err := VerifySignature(bytes.NewReader(message), fileSignature,
			&VerifyOptions{SSHKeys: []ssh.PublicKey{signer.PublicKey()}})
		require.ErrorIs(t, err, ErrSSHNamespace)
	})

	t.Run("empty namespace rejected", func(t *testing.T) {
		t.Parallel()
		emptyNSSignature := generateSSHSignatureForTest(t, signer, "", "sha512", message)
		_, err := VerifySignature(bytes.NewReader(message), emptyNSSignature,
			&VerifyOptions{SSHKeys: []ssh.PublicKey{signer.PublicKey()}})
		require.ErrorIs(t, err, ErrSSHNamespace)
	})
}

func TestParseAllowedSigners(t *testing.T) {
	t.Parallel()
	input := strings.NewReader(`# a comment

go-git-test@example.com ` + gitSSHPublicKey + `
admin@example.com,deploy@example.com namespaces="git" ` + gitSSHPublicKey + `
`)

	signers, err := ParseAllowedSigners(input)
	require.NoError(t, err)
	require.Len(t, signers, 2)
	assert.Equal(t, []string{"go-git-test@example.com"}, signers[0].Principals)
	assert.NotNil(t, signers[0].Key)
	assert.Equal(t, []string{"admin@example.com", "deploy@example.com"}, signers[1].Principals)
}

// generateSSHSignatureForTest produces an armored SSHSIG blob, mirroring the
// PROTOCOL.sshsig signing side.
func generateSSHSignatureForTest(t *testing.T, signer ssh.Signer, namespace, hashAlgorithm string, message []byte) []byte {
	t.Helper()

	hashFunc, err := sshHashFunc(hashAlgorithm)
	require.NoError(t, err)
	h := hashFunc.New()
	_, err = h.Write(message)
	require.NoError(t, err)

	preimage := encodeSSHSignedData(namespace, "", hashAlgorithm, h.Sum(nil))
	sshSig, err := signer.Sign(rand.Reader, preimage)
	require.NoError(t, err)
	signatureWire := ssh.Marshal(sshSig)

	var blob bytes.Buffer
	blob.WriteString(sshSignatureMagic)
	require.NoError(t, binary.Write(&blob, binary.BigEndian, uint32(1)))
	writeTestSSHString := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		blob.Write(length[:])
		blob.Write(value)
	}
	writeTestSSHString(signer.PublicKey().Marshal())
	writeTestSSHString([]byte(namespace))
	writeTestSSHString(nil)
	writeTestSSHString([]byte(hashAlgorithm))
	writeTestSSHString(signatureWire)

	return pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: blob.Bytes()})
}
