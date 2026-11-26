package object

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	pkcs7 "go.mozilla.org/pkcs7"
)

// LoadX509RootsFile reads a PEM file of one or more certificates and returns
// them as a trust pool. It is used to supply X.509/CMS trust roots from a
// caller-managed file or repository configuration.
func LoadX509RootsFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadX509RootsPEM(data)
}

// LoadX509RootsPEM parses PEM-encoded certificates into a trust pool. Any
// non-certificate PEM blocks are skipped.
func LoadX509RootsPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no X.509 certificates found in PEM data")
	}
	return pool, nil
}

func verifyX509Scheme(message io.Reader, signature []byte, opts *VerifyOptions) (*Verification, error) {
	block, _ := pem.Decode(signature)
	if block == nil {
		return nil, errors.New("x509 signature: no PEM block found")
	}

	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509 signature: parsing CMS message: %w", err)
	}

	// Git X.509 signatures are detached CMS signatures over the exact
	// object payload, so the externally supplied message is the signed
	// content.
	payload, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	p7.Content = payload

	// Verify the CMS signature and message digest without chain
	// verification; trust anchors are applied below so callers control
	// roots, key usages and validity time.
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("x509 signature verification failed: %w", err)
	}

	cert := p7.GetOnlySigner()
	if cert == nil {
		return nil, errors.New("x509 signature: could not identify a unique signer certificate")
	}

	verifyOpts := x509.VerifyOptions{}
	if opts != nil {
		verifyOpts = opts.X509VerifyOptions
	}

	if opts != nil && opts.X509Roots != nil {
		verifyOpts.Roots = opts.X509Roots
	}

	intermediates := x509.NewCertPool()
	if verifyOpts.Intermediates != nil {
		intermediates = verifyOpts.Intermediates.Clone()
	}
	for _, embedded := range p7.Certificates {
		intermediates.AddCert(embedded)
	}
	verifyOpts.Intermediates = intermediates

	if len(verifyOpts.KeyUsages) == 0 {
		// Accept both email-protection (S/MIME) and code-signing
		// certificates rather than defaulting to server authentication.
		verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	if _, err := cert.Verify(verifyOpts); err != nil {
		return nil, fmt.Errorf("x509 signer is not trusted: %w", err)
	}

	return &Verification{
		Signer:  x509SignerIdentity(cert),
		Format:  SignatureTypeX509,
		Method:  SignatureTypeX509,
		Details: cert,
	}, nil
}

func x509SignerIdentity(cert *x509.Certificate) string {
	if len(cert.EmailAddresses) > 0 && cert.EmailAddresses[0] != "" {
		return cert.EmailAddresses[0]
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}
