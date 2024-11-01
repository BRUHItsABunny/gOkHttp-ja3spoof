package tls_compat

import (
	"crypto/tls"
	utls "github.com/refraction-networking/utls"
)

func STDSignatureSchemesToSignatureSchemes(schemes []tls.SignatureScheme) []utls.SignatureScheme {
	result := make([]utls.SignatureScheme, len(schemes))
	for i, scheme := range schemes {
		result[i] = utls.SignatureScheme(scheme)
	}
	return result
}

func STDCertificatesToCertificates(certs []tls.Certificate) []utls.Certificate {
	result := make([]utls.Certificate, len(certs))
	for i, cert := range certs {
		result[i] = utls.Certificate{
			Certificate:                  cert.Certificate,
			PrivateKey:                   cert.PrivateKey,
			SupportedSignatureAlgorithms: STDSignatureSchemesToSignatureSchemes(cert.SupportedSignatureAlgorithms),
			OCSPStaple:                   cert.OCSPStaple,
			SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
			Leaf:                         cert.Leaf,
		}
	}
	return result
}

func STDMapCertificatesToMapCertificates(certs map[string]*tls.Certificate) map[string]*utls.Certificate {
	result := make(map[string]*utls.Certificate)
	for i, cert := range certs {
		result[i] = &utls.Certificate{
			Certificate:                  cert.Certificate,
			PrivateKey:                   cert.PrivateKey,
			SupportedSignatureAlgorithms: STDSignatureSchemesToSignatureSchemes(cert.SupportedSignatureAlgorithms),
			OCSPStaple:                   cert.OCSPStaple,
			SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
			Leaf:                         cert.Leaf,
		}
	}
	return result
}
