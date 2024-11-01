package tls_compat

import (
	"crypto/tls"
	utls "github.com/refraction-networking/utls"
)

func STDCurveIdsToCurveIds(schemes []tls.CurveID) []utls.CurveID {
	result := make([]utls.CurveID, len(schemes))
	for i, scheme := range schemes {
		result[i] = utls.CurveID(scheme)
	}
	return result
}

func STDConfigToConfig(config *tls.Config) *utls.Config {
	return &utls.Config{
		Rand:              config.Rand,
		Time:              config.Time,
		Certificates:      STDCertificatesToCertificates(config.Certificates),
		NameToCertificate: STDMapCertificatesToMapCertificates(config.NameToCertificate),
		// GetCertificate:                     config.GetCertificate,
		// GetClientCertificate:               config.GetClientCertificate,
		// GetConfigForClient:                 config.GetConfigForClient,
		VerifyPeerCertificate: config.VerifyPeerCertificate,
		// VerifyConnection:                   config.VerifyConnection,
		RootCAs:                  config.RootCAs,
		NextProtos:               config.NextProtos,
		ServerName:               config.ServerName,
		ClientAuth:               utls.ClientAuthType(config.ClientAuth),
		ClientCAs:                config.ClientCAs,
		InsecureSkipVerify:       config.InsecureSkipVerify,
		CipherSuites:             config.CipherSuites,
		PreferServerCipherSuites: config.PreferServerCipherSuites,
		SessionTicketsDisabled:   config.SessionTicketsDisabled,
		SessionTicketKey:         config.SessionTicketKey,
		// ClientSessionCache:                 config.ClientSessionCache,
		// UnwrapSession:                      config.UnwrapSession,
		// WrapSession:                        config.WrapSession,
		MinVersion:                  config.MinVersion,
		MaxVersion:                  config.MaxVersion,
		CurvePreferences:            STDCurveIdsToCurveIds(config.CurvePreferences),
		DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
		Renegotiation:               utls.RenegotiationSupport(config.Renegotiation),
		KeyLogWriter:                config.KeyLogWriter,
	}
}
