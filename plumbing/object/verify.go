package object

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"golang.org/x/crypto/ssh"

	"github.com/go-git/go-git/v6/plumbing"
)

// SignatureType identifies the cryptographic scheme of an embedded object
// signature.
type SignatureType int

const (
	// SignatureTypeUnknown is an unrecognised or unset signature scheme.
	SignatureTypeUnknown SignatureType = iota
	// SignatureTypeOpenPGP is an OpenPGP/GPG armored signature.
	SignatureTypeOpenPGP
	// SignatureTypeSSH is an SSH signature (PROTOCOL.sshsig).
	SignatureTypeSSH
	// SignatureTypeX509 is an X.509/CMS (PKCS#7, S/MIME) signature.
	SignatureTypeX509
)

// String returns the canonical Git/gpg format name for the signature type,
// matching the values accepted by gpg.format ("openpgp", "ssh", "x509").
func (t SignatureType) String() string {
	switch t {
	case SignatureTypeOpenPGP:
		return "openpgp"
	case SignatureTypeSSH:
		return "ssh"
	case SignatureTypeX509:
		return "x509"
	default:
		return "unknown"
	}
}

// SignatureFormat is an alias for SignatureType, named after the signature
// format detection table.
type SignatureFormat = SignatureType

// Verification is the scheme-neutral result of successfully verifying an
// object signature. A non-nil Verification is only returned when the
// cryptographic signature is valid and the signer is trusted by the material
// supplied in VerifyOptions.
type Verification struct {
	// Signer is the verified signer identifier in a scheme-neutral form.
	// It holds the primary OpenPGP user id, the SHA-256 SSH key
	// fingerprint (SSH signatures carry no intrinsic identity) or the
	// X.509 signer e-mail/common name. Scheme-specific material is
	// available through Details.
	Signer string

	// Format is the signature scheme that was verified.
	Format SignatureType

	// Method mirrors Format. It is provided under the scheme-agnostic
	// verifier vocabulary used by go-git's plugin API.
	Method SignatureType

	// Fingerprint is the SHA-256 fingerprint of an SSH signing key
	// ("SHA256:..."). It is empty for other schemes.
	Fingerprint string

	// Principals lists the SSH allowed-signers principals associated with
	// a trusted SSH key. It is empty when the key was supplied directly
	// rather than through an allowed-signers file.
	Principals []string

	// Details carries the scheme-specific signer material:
	//   - SignatureTypeOpenPGP: *openpgp.Entity
	//   - SignatureTypeSSH:     ssh.PublicKey
	//   - SignatureTypeX509:    *crypto/x509.Certificate
	Details any
}

// VerifyOptions carries the trust material used by the scheme-agnostic
// verification entry point. The zero value provides no trust anchors, so
// OpenPGP and SSH signatures cannot be trusted; X.509 verification falls back
// to the operating system verifier roots.
type VerifyOptions struct {
	// ArmoredKeyRing is an ASCII-armored OpenPGP keyring. Used when
	// KeyRing is nil.
	ArmoredKeyRing string
	// KeyRing is a pre-parsed OpenPGP keyring. When set it takes
	// precedence over ArmoredKeyRing.
	KeyRing openpgp.KeyRing

	// SSHKeys are trusted SSH public keys. An SSH signature is trusted
	// when its embedded key matches one of these keys or one of
	// SSHAllowedSigners.
	SSHKeys []ssh.PublicKey
	// SSHAllowedSigners are trusted keys parsed from Git's allowed-signers
	// file (gpg.ssh.allowedSignersFile). Their principals are exposed on
	// the returned Verification.
	SSHAllowedSigners []AllowedSigner

	// X509Roots are the trusted root certificates for X.509/CMS
	// signatures. When nil, X509VerifyOptions.Roots is used; if that is
	// also nil the system certificate pool is used.
	X509Roots *x509.CertPool
	// X509VerifyOptions customises certificate chain and key-usage
	// verification for X.509 signatures. Its Roots field is overridden by
	// X509Roots when set. Certificates embedded in the CMS message are
	// always added as intermediates.
	X509VerifyOptions x509.VerifyOptions
}

// ErrNotSigned is returned when the object carries no signature block.
var ErrNotSigned = errors.New("object is not signed")

// ErrUnknownSignatureFormat is returned when a signature is present but its
// armored format is not one of the recognised PGP, SSH or X.509 encodings.
var ErrUnknownSignatureFormat = errors.New("unknown signature format")

// ErrUntrustedSigner is returned when the signature is cryptographically valid
// but no supplied trust material matches the signer.
var ErrUntrustedSigner = errors.New("untrusted signer")

// Verifier verifies detached object signatures against a fixed set of trust
// material. It dispatches on the detected signature scheme (OpenPGP, SSH or
// X.509/CMS) and returns a scheme-neutral Verification.
//
// A Verifier is safe for concurrent use as long as the supplied trust
// material (key rings, key pools) is not mutated afterwards.
type Verifier struct {
	opts VerifyOptions
}

// NewVerifier builds a scheme-agnostic Verifier. Armored OpenPGP keyrings are
// parsed eagerly so that malformed trust material is reported here.
func NewVerifier(opts *VerifyOptions) (*Verifier, error) {
	verifier := &Verifier{}
	if opts != nil {
		verifier.opts = *opts
	}
	if verifier.opts.KeyRing == nil && verifier.opts.ArmoredKeyRing != "" {
		ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(verifier.opts.ArmoredKeyRing))
		if err != nil {
			return nil, fmt.Errorf("reading armored OpenPGP keyring: %w", err)
		}
		verifier.opts.KeyRing = ring
	}
	return verifier, nil
}

// Verify checks the detached signature over message and returns the verified
// signer. It returns ErrNotSigned for an empty signature,
// ErrUnknownSignatureFormat for an unrecognised armor block and
// ErrMultipleSignatures when more than one signature block is present.
func (v *Verifier) Verify(message io.Reader, signature []byte) (*Verification, error) {
	if len(bytes.TrimSpace(signature)) == 0 {
		return nil, ErrNotSigned
	}
	if countSignatureBlocks(signature) > 1 {
		return nil, ErrMultipleSignatures
	}

	scheme := signatureScheme(signature)
	switch scheme {
	case SignatureTypeOpenPGP:
		return verifyOpenPGPScheme(message, signature, &v.opts)
	case SignatureTypeSSH:
		return verifySSHScheme(message, signature, &v.opts)
	case SignatureTypeX509:
		return verifyX509Scheme(message, signature, &v.opts)
	default:
		return nil, fmt.Errorf("%w: unrecognised armored signature block", ErrUnknownSignatureFormat)
	}
}

// VerifySignature is the one-shot form of NewVerifier followed by
// Verifier.Verify. It is the scheme-agnostic counterpart of Commit.Verify and
// Tag.Verify: PGP, SSH and X.509 signatures are all accepted and reported
// through a single Verification result. A nil opts means no explicit trust
// material.
func VerifySignature(message io.Reader, signature []byte, opts *VerifyOptions) (*Verification, error) {
	verifier, err := NewVerifier(opts)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(message, signature)
}

// VerifySignature verifies the commit's embedded signature using the
// scheme-agnostic verifier. Unlike Verify, the returned Verification can
// describe PGP, SSH and X.509 signers.
func (c *Commit) VerifySignature(opts *VerifyOptions) (*Verification, error) {
	message, err := signaturePayloadReader(c)
	if err != nil {
		return nil, err
	}
	return VerifySignature(message, []byte(c.Signature), opts)
}

// VerifySignature verifies the tag's embedded signature using the
// scheme-agnostic verifier. Unlike Verify, the returned Verification can
// describe PGP, SSH and X.509 signers.
func (t *Tag) VerifySignature(opts *VerifyOptions) (*Verification, error) {
	message, err := signaturePayloadReader(t)
	if err != nil {
		return nil, err
	}
	return VerifySignature(message, []byte(t.Signature), opts)
}

type signatureWithoutEnvelope interface {
	EncodeWithoutSignature(o plumbing.EncodedObject) error
}

func signaturePayloadReader(obj signatureWithoutEnvelope) (io.Reader, error) {
	encoded := &plumbing.MemoryObject{}
	if err := obj.EncodeWithoutSignature(encoded); err != nil {
		return nil, err
	}
	return encoded.Reader()
}

// signatureScheme detects the exported SignatureType for an embedded signature
// value, tolerating a leading newline (as stored in object headers).
func signatureScheme(signature []byte) SignatureType {
	_, internal := parseSignedBytes(signature)
	if internal == signatureTypeUnknown {
		internal = typeForSignature(bytes.TrimLeft(signature, "\r\n \t"))
	}
	return exportSignatureType(internal)
}

func exportSignatureType(t signatureType) SignatureType {
	switch t {
	case signatureTypeOpenPGP:
		return SignatureTypeOpenPGP
	case signatureTypeSSH:
		return SignatureTypeSSH
	case signatureTypeX509:
		return SignatureTypeX509
	default:
		return SignatureTypeUnknown
	}
}

func verifyOpenPGPScheme(message io.Reader, signature []byte, opts *VerifyOptions) (*Verification, error) {
	ring, err := openPGPKeyRing(opts)
	if err != nil {
		return nil, err
	}

	entity, err := openpgp.CheckArmoredDetachedSignature(
		ring, message, bytes.NewReader(signature), nil,
	)
	if err != nil {
		return nil, err
	}

	verification := &Verification{
		Format:  SignatureTypeOpenPGP,
		Method:  SignatureTypeOpenPGP,
		Details: entity,
	}
	if name := primaryOpenPGPIdentity(entity); name != "" {
		verification.Signer = name
	}
	return verification, nil
}

func openPGPKeyRing(opts *VerifyOptions) (openpgp.KeyRing, error) {
	if opts != nil && opts.KeyRing != nil {
		return opts.KeyRing, nil
	}
	armored := ""
	if opts != nil {
		armored = opts.ArmoredKeyRing
	}
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("reading armored OpenPGP keyring: %w", err)
	}
	return ring, nil
}

func primaryOpenPGPIdentity(entity *openpgp.Entity) string {
	if entity == nil || len(entity.Identities) == 0 {
		return ""
	}
	names := make([]string, 0, len(entity.Identities))
	for name := range entity.Identities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names[0]
}
