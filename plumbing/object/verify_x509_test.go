package object

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs7 "go.mozilla.org/pkcs7"

	"github.com/go-git/go-git/v6/plumbing"
)

type testCertificate struct {
	cert *x509.Certificate
	key  any
	pool *x509.CertPool
}

func generateTestCertificate(t *testing.T, email string) testCertificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Go Git Test",
			Organization: []string{"go-git"},
		},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning},
		EmailAddresses: []string{email},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCertificate{cert: cert, key: priv, pool: pool}
}

func encodeDetachedCMSTestSignature(t *testing.T, payload []byte, cert *x509.Certificate, key any) []byte {
	t.Helper()
	signedData, err := pkcs7.NewSignedData(payload)
	require.NoError(t, err)
	require.NoError(t, signedData.AddSigner(cert, key, pkcs7.SignerInfoConfig{}))
	signedData.Detach()
	der, err := signedData.Finish()
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der})
}

func TestVerifySignatureX509Commit(t *testing.T) {
	t.Parallel()
	signer := generateTestCertificate(t, "go-git-test@example.com")

	commit := &Commit{
		Author:    Signature{Name: "go-git", Email: "go-git@example.com"},
		Committer: Signature{Name: "go-git", Email: "go-git@example.com"},
		Message:   "x509 signed commit\n",
		TreeHash:  plumbing.NewHash("52a266a58f2c028ad7de4dfd3a72fdf76b0d4e24"),
	}
	payloadReader, err := signaturePayloadReader(commit)
	require.NoError(t, err)
	payload, err := io.ReadAll(payloadReader)
	require.NoError(t, err)

	commit.Signature = string(encodeDetachedCMSTestSignature(t, payload, signer.cert, signer.key))

	verification, err := commit.VerifySignature(&VerifyOptions{X509Roots: signer.pool})
	require.NoError(t, err)
	assert.Equal(t, SignatureTypeX509, verification.Format)
	assert.Equal(t, "go-git-test@example.com", verification.Signer)
	require.IsType(t, &x509.Certificate{}, verification.Details)
	assert.Equal(t, signer.cert.Raw, verification.Details.(*x509.Certificate).Raw)
}

func TestVerifySignatureX509Tag(t *testing.T) {
	t.Parallel()
	signer := generateTestCertificate(t, "tag-signer@example.com")

	tag := &Tag{
		Name:       "v1",
		Tagger:     Signature{Name: "go-git", Email: "go-git@example.com"},
		Message:    "x509 signed tag\n",
		TargetType: plumbing.CommitObject,
		Target:     plumbing.NewHash("1eca38290a3131d0c90709496a9b2207a872631e"),
	}
	payloadReader, err := signaturePayloadReader(tag)
	require.NoError(t, err)
	payload, err := io.ReadAll(payloadReader)
	require.NoError(t, err)

	tag.Signature = string(encodeDetachedCMSTestSignature(t, payload, signer.cert, signer.key))

	verification, err := tag.VerifySignature(&VerifyOptions{X509Roots: signer.pool})
	require.NoError(t, err)
	assert.Equal(t, SignatureTypeX509, verification.Format)
	assert.Equal(t, "tag-signer@example.com", verification.Signer)
}

func TestVerifySignatureX509Failures(t *testing.T) {
	t.Parallel()
	signer := generateTestCertificate(t, "go-git-test@example.com")
	message := []byte("object payload\n")
	signature := encodeDetachedCMSTestSignature(t, message, signer.cert, signer.key)

	t.Run("untrusted roots", func(t *testing.T) {
		t.Parallel()
		emptyPool := x509.NewCertPool()
		_, err := VerifySignature(bytes.NewReader(message), signature, &VerifyOptions{X509Roots: emptyPool})
		require.Error(t, err)
		assert.ErrorContains(t, err, "not trusted")
	})

	t.Run("tampered content", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySignature(bytes.NewReader(append(append([]byte{}, message...), 'x')), signature,
			&VerifyOptions{X509Roots: signer.pool})
		require.Error(t, err)
		assert.ErrorContains(t, err, "digest mismatch")
	})

	t.Run("expired certificate", func(t *testing.T) {
		t.Parallel()
		expired := generateExpiredCertificateForTest(t)
		expiredSig := encodeDetachedCMSTestSignature(t, message, expired.cert, expired.key)
		_, err := VerifySignature(bytes.NewReader(message), expiredSig, &VerifyOptions{
			X509Roots: expired.pool,
			X509VerifyOptions: x509.VerifyOptions{
				CurrentTime: time.Now(),
			},
		})
		require.Error(t, err)
	})
}

func TestVerifySignatureX509ECDSA(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ecdsa signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	message := []byte("ecdsa payload\n")
	signature := encodeDetachedCMSTestSignature(t, message, cert, priv)
	verification, err := VerifySignature(bytes.NewReader(message), signature, &VerifyOptions{X509Roots: pool})
	require.NoError(t, err)
	assert.Equal(t, "ecdsa signer", verification.Signer)
}

func generateExpiredCertificateForTest(t *testing.T) testCertificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "expired signer"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCertificate{cert: cert, key: priv, pool: pool}
}
