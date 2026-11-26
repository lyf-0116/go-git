package object

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// sshSignatureNamespace is the only SSH signature namespace accepted for Git
// commit and tag signatures. Git passes "-n git" to ssh-keygen(1); enforcing
// it prevents signatures minted for another namespace (for example "file" or
// an arbitrary application namespace) from being replayed as object
// signatures. See PROTOCOL.sshsig and git's gpg-interface.c.
const sshSignatureNamespace = "git"

// ErrSSHNamespace is returned when an SSH signature was produced for a
// namespace other than "git".
var ErrSSHNamespace = errors.New("ssh signature has invalid namespace")

// AllowedSigner is a single parsed entry of an OpenSSH allowed-signers file
// (gpg.ssh.allowedSignersFile): one key authorised for Principals.
type AllowedSigner struct {
	// Principals are the identities (typically e-mail addresses) allowed
	// to use Key.
	Principals []string
	// Key is the authorised SSH public key.
	Key ssh.PublicKey
}

// LoadAllowedSignersFile reads and parses an ssh-keygen allowed-signers file.
func LoadAllowedSignersFile(path string) ([]AllowedSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAllowedSigners(bytes.NewReader(data))
}

// ParseAllowedSigners parses the allowed-signers line format:
//
//	principal[,principal...] [option...] keytype base64-key [comment]
//
// Blank lines and lines starting with '#' are ignored.
func ParseAllowedSigners(r io.Reader) ([]AllowedSigner, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var signers []AllowedSigner
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("allowed-signers:%d: malformed line", lineNo+1)
		}

		principals := strings.Split(fields[0], ",")

		// Options may sit between the principals and the key. The
		// public key is the first suffix that parses as an authorized
		// key (type + base64 + optional comment).
		var key ssh.PublicKey
		for i := 1; i < len(fields)-1; i++ {
			candidate := strings.Join(fields[i:], " ")
			parsed, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(candidate))
			if perr == nil {
				key = parsed
				break
			}
		}
		if key == nil {
			return nil, fmt.Errorf("allowed-signers:%d: no parseable public key", lineNo+1)
		}

		signers = append(signers, AllowedSigner{Principals: principals, Key: key})
	}
	return signers, nil
}

// sshSignatureBlob is the parsed PROTOCOL.sshsig wire blob (without the PEM
// armor and base64).
type sshSignatureBlob struct {
	version       uint32
	publicKey     ssh.PublicKey
	namespace     string
	reserved      string
	hashAlgorithm string
	signature     *ssh.Signature
}

func verifySSHScheme(message io.Reader, signature []byte, opts *VerifyOptions) (*Verification, error) {
	blob, err := parseSSHSignature(signature)
	if err != nil {
		return nil, err
	}

	if blob.namespace != sshSignatureNamespace {
		return nil, fmt.Errorf("%w: expected %q, got %q",
			ErrSSHNamespace, sshSignatureNamespace, blob.namespace)
	}

	hashFunc, err := sshHashFunc(blob.hashAlgorithm)
	if err != nil {
		return nil, err
	}

	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, message); err != nil {
		return nil, err
	}
	digest := hasher.Sum(nil)

	signedData := encodeSSHSignedData(blob.namespace, blob.reserved, blob.hashAlgorithm, digest)
	if err := blob.publicKey.Verify(signedData, blob.signature); err != nil {
		return nil, fmt.Errorf("ssh signature verification failed: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(blob.publicKey)
	principals, trusted := matchSSHTrust(blob.publicKey, opts)
	if !trusted {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedSigner, fingerprint)
	}

	return &Verification{
		Signer:      fingerprint,
		Format:      SignatureTypeSSH,
		Method:      SignatureTypeSSH,
		Fingerprint: fingerprint,
		Principals:  principals,
		Details:     blob.publicKey,
	}, nil
}

func matchSSHTrust(key ssh.PublicKey, opts *VerifyOptions) ([]string, bool) {
	wire := key.Marshal()
	var principals []string
	trusted := false

	if opts == nil {
		return nil, false
	}
	for _, trustedKey := range opts.SSHKeys {
		if trustedKey != nil && bytes.Equal(trustedKey.Marshal(), wire) {
			trusted = true
		}
	}
	for _, signer := range opts.SSHAllowedSigners {
		if signer.Key != nil && bytes.Equal(signer.Key.Marshal(), wire) {
			trusted = true
			principals = append(principals, signer.Principals...)
		}
	}
	return principals, trusted
}

func sshHashFunc(name string) (crypto.Hash, error) {
	switch name {
	case "sha256":
		return crypto.SHA256, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported ssh signature hash algorithm %q", name)
	}
}

// encodeSSHSignedData builds the blob that an SSH signature is computed over,
// per PROTOCOL.sshsig:
//
//	byte[6] MAGIC_PREAMBLE ("SSHSIG", raw, not length-prefixed)
//	string namespace
//	string reserved
//	string hash_algorithm
//	string hash
func encodeSSHSignedData(namespace, reserved, hashAlgorithm string, digest []byte) []byte {
	var signed bytes.Buffer
	signed.WriteString(sshSignatureMagic)
	writeSSHString := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		signed.Write(length[:])
		signed.Write(value)
	}
	writeSSHString([]byte(namespace))
	writeSSHString([]byte(reserved))
	writeSSHString([]byte(hashAlgorithm))
	writeSSHString(digest)
	return signed.Bytes()
}

const sshSignatureMagic = "SSHSIG"

// parseSSHSignature decodes an armored "-----BEGIN SSH SIGNATURE-----" block
// into its PROTOCOL.sshsig fields.
func parseSSHSignature(signature []byte) (*sshSignatureBlob, error) {
	block, _ := pem.Decode(signature)
	if block == nil {
		return nil, errors.New("ssh signature: no PEM block found")
	}
	raw := block.Bytes

	if len(raw) < len(sshSignatureMagic)+4 || string(raw[:len(sshSignatureMagic)]) != sshSignatureMagic {
		return nil, errors.New("ssh signature: invalid SSHSIG magic preamble")
	}
	rest := raw[len(sshSignatureMagic):]

	version, rest, ok := readSSHUint32(rest)
	if !ok {
		return nil, errors.New("ssh signature: truncated version")
	}
	if version != 1 {
		return nil, fmt.Errorf("ssh signature: unsupported version %d", version)
	}

	publicKeyBlob, rest, ok := readSSHString(rest)
	if !ok {
		return nil, errors.New("ssh signature: truncated public key")
	}
	namespace, rest, ok := readSSHString(rest)
	if !ok {
		return nil, errors.New("ssh signature: truncated namespace")
	}
	reserved, rest, ok := readSSHString(rest)
	if !ok {
		return nil, errors.New("ssh signature: truncated reserved field")
	}
	hashAlgorithm, rest, ok := readSSHString(rest)
	if !ok {
		return nil, errors.New("ssh signature: truncated hash algorithm")
	}
	signatureBlob, _, ok := readSSHString(rest)
	if !ok {
		return nil, errors.New("ssh signature: truncated signature")
	}

	publicKey, err := ssh.ParsePublicKey(publicKeyBlob)
	if err != nil {
		return nil, fmt.Errorf("ssh signature: parsing public key: %w", err)
	}

	sshSig := new(ssh.Signature)
	if err := ssh.Unmarshal(signatureBlob, sshSig); err != nil {
		return nil, fmt.Errorf("ssh signature: parsing signature blob: %w", err)
	}

	return &sshSignatureBlob{
		version:       version,
		publicKey:     publicKey,
		namespace:     string(namespace),
		reserved:      string(reserved),
		hashAlgorithm: string(hashAlgorithm),
		signature:     sshSig,
	}, nil
}

func readSSHUint32(b []byte) (uint32, []byte, bool) {
	if len(b) < 4 {
		return 0, b, false
	}
	return binary.BigEndian.Uint32(b[:4]), b[4:], true
}

func readSSHString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, b, false
	}
	length := binary.BigEndian.Uint32(b[:4])
	if uint64(length) > uint64(len(b)-4) {
		return nil, b, false
	}
	return b[4 : 4+length], b[4+length:], true
}
