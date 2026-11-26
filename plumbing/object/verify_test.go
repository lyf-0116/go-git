package object

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifySignatureOpenPGPDispatch(t *testing.T) {
	t.Parallel()
	entity, err := openpgp.NewEntity("go-git test", "", "go-git@example.com", nil)
	require.NoError(t, err)

	message := []byte("tree abc\n\nsigned payload\n")
	var armoredSignature bytes.Buffer
	require.NoError(t, openpgp.ArmoredDetachSign(&armoredSignature, entity, bytes.NewReader(message), nil))

	verification, err := VerifySignature(bytes.NewReader(message), armoredSignature.Bytes(),
		&VerifyOptions{KeyRing: openpgp.EntityList{entity}})
	require.NoError(t, err)

	assert.Equal(t, SignatureTypeOpenPGP, verification.Format)
	assert.Equal(t, SignatureTypeOpenPGP, verification.Method)
	require.IsType(t, &openpgp.Entity{}, verification.Details)
	assert.NotEmpty(t, verification.Signer)
}

func TestVerifySignatureErrors(t *testing.T) {
	t.Parallel()
	message := bytes.NewReader([]byte("payload"))

	t.Run("unsigned", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySignature(message, nil, nil)
		require.ErrorIs(t, err, ErrNotSigned)

		_, err = VerifySignature(message, []byte("   \n\t"), nil)
		require.ErrorIs(t, err, ErrNotSigned)
	})

	t.Run("unknown format", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySignature(bytes.NewReader([]byte("payload")),
			[]byte("-----BEGIN ARBITRARY-----\nAAAA\n-----END ARBITRARY-----\n"), nil)
		require.ErrorIs(t, err, ErrUnknownSignatureFormat)
	})

	t.Run("multiple signatures", func(t *testing.T) {
		t.Parallel()
		multi := []byte("-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n" +
			"-----BEGIN SSH SIGNATURE-----\nBBBB\n-----END SSH SIGNATURE-----\n")
		_, err := VerifySignature(bytes.NewReader([]byte("payload")), multi, nil)
		require.ErrorIs(t, err, ErrMultipleSignatures)
	})

	t.Run("ssh without trust material is untrusted", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySignature(bytes.NewReader([]byte("payload")),
			[]byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"), nil)
		require.Error(t, err)
	})

	t.Run("malformed ssh signature does not panic", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySignature(bytes.NewReader([]byte("payload")),
			[]byte("-----BEGIN SSH SIGNATURE-----\nnot-base64!!!\n-----END SSH SIGNATURE-----\n"), nil)
		require.Error(t, err)
	})
}

func TestSignatureTypeString(t *testing.T) {
	t.Parallel()
	cases := map[SignatureType]string{
		SignatureTypeUnknown: "unknown",
		SignatureTypeOpenPGP: "openpgp",
		SignatureTypeSSH:     "ssh",
		SignatureTypeX509:    "x509",
	}
	for typ, want := range cases {
		assert.Equal(t, want, typ.String())
	}
}

func TestSignatureSchemeDetection(t *testing.T) {
	t.Parallel()
	assert.Equal(t, SignatureTypeOpenPGP,
		signatureScheme([]byte("\n-----BEGIN PGP SIGNATURE-----\n")))
	assert.Equal(t, SignatureTypeSSH,
		signatureScheme([]byte("-----BEGIN SSH SIGNATURE-----\n")))
	assert.Equal(t, SignatureTypeX509,
		signatureScheme([]byte("-----BEGIN SIGNED MESSAGE-----\n")))
	assert.Equal(t, SignatureTypeX509,
		signatureScheme([]byte("-----BEGIN CMS-----\n")))
	assert.Equal(t, SignatureTypeUnknown,
		signatureScheme([]byte("-----BEGIN CERTIFICATE-----\n")))
}
