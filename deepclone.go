package gokhttp_ja3spoof

/*
func DeepCloneClientHelloSpec(chs *utls.ClientHelloSpec) *utls.ClientHelloSpec {
	// Deep copy the slices
	cipherSuitesCopy := make([]uint16, len(chs.CipherSuites))
	copy(cipherSuitesCopy, chs.CipherSuites)

	compressionMethodsCopy := make([]uint8, len(chs.CompressionMethods))
	copy(compressionMethodsCopy, chs.CompressionMethods)

	// Clone the extensions manually
	extensionsCopy := make([]utls.TLSExtension, len(chs.Extensions))
	for i, ext := range chs.Extensions {
		extensionsCopy[i] = DeepCloneTLSExtension(ext)
	}

	// Return the deep copy
	return &utls.ClientHelloSpec{
		CipherSuites:       cipherSuitesCopy,
		CompressionMethods: compressionMethodsCopy,
		Extensions:         extensionsCopy,
		TLSVersMin:         chs.TLSVersMin,
		TLSVersMax:         chs.TLSVersMax,
		GetSessionID:       chs.GetSessionID, // Simply assign the function pointer
	}
}

func DeepCloneTLSExtension(ext utls.TLSExtension) utls.TLSExtension {
	switch typedExt := ext.(type) {
	case *utls.SNIExtension:
		return &utls.SNIExtension{
			ServerName: typedExt.ServerName,
		}

	case *utls.SignatureAlgorithmsCertExtension:
		return &utls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: cloneSignatureSchemes(typedExt.SupportedSignatureAlgorithms),
		}

	case *utls.QUICTransportParametersExtension:
		return &utls.QUICTransportParametersExtension{
			TransportParameters: utls.TransportParameters{
				utls.TransportParameter,
			},
		}

	case *utls.ALPNExtension:
		return &utls.ALPNExtension{
			AlpnProtocols: cloneStringSlice(typedExt.AlpnProtocols),
		}

	case *utls.ApplicationSettingsExtension:
		return &utls.ApplicationSettingsExtension{
			SupportedProtocols: cloneStringSlice(typedExt.SupportedProtocols),
		}

	case *utls.SupportedCurvesExtension:
		return &utls.SupportedCurvesExtension{
			Curves: cloneCurveIDs(typedExt.Curves),
		}

	case *utls.SupportedPointsExtension:
		return &utls.SupportedPointsExtension{
			SupportedPoints: cloneUint8Slice(typedExt.SupportedPoints),
		}

	case *utls.SignatureAlgorithmsExtension:
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: cloneSignatureSchemes(typedExt.SupportedSignatureAlgorithms),
		}

	case *utls.StatusRequestExtension:
		return &utls.StatusRequestExtension{}

	case *utls.StatusRequestV2Extension:
		return &utls.StatusRequestV2Extension{}

	case *utls.KeyShareExtension:
		return &utls.KeyShareExtension{
			KeyShares: cloneKeyShares(typedExt.KeyShares),
		}

	case *utls.SessionTicketExtension:
		return &utls.SessionTicketExtension{}

	case *utls.PSKKeyExchangeModesExtension:
		return &utls.PSKKeyExchangeModesExtension{
			Modes: cloneUint8Slice(typedExt.Modes),
		}

	case *utls.SupportedVersionsExtension:
		return &utls.SupportedVersionsExtension{
			Versions: cloneUint16Slice(typedExt.Versions),
		}

	case *utls.CookieExtension:
		return &utls.CookieExtension{
			Cookie: cloneByteSlice(typedExt.Cookie),
		}

	case *utls.SCTExtension:
		return &utls.SCTExtension{}

	case *utls.RenegotiationInfoExtension:
		return &utls.RenegotiationInfoExtension{
			Renegotiation:          typedExt.Renegotiation,
			RenegotiatedConnection: cloneByteSlice(typedExt.RenegotiatedConnection),
		}

	case *utls.ExtendedMasterSecretExtension:
		return &utls.ExtendedMasterSecretExtension{}

	case *utls.GenericExtension:
		return &utls.GenericExtension{
			Id:   typedExt.Id,
			Data: cloneByteSlice(typedExt.Data),
		}

	case *utls.UtlsGREASEExtension:
		return &utls.UtlsGREASEExtension{
			Value: typedExt.Value,
			Body:  cloneByteSlice(typedExt.Body),
		}

	case *utls.UtlsPaddingExtension:
		return &utls.UtlsPaddingExtension{
			PaddingLen:    typedExt.PaddingLen,
			WillPad:       typedExt.WillPad,
			GetPaddingLen: typedExt.GetPaddingLen,
		}

	case *utls.UtlsCompressCertExtension:
		return &utls.UtlsCompressCertExtension{
			Algorithms: cloneCertCompressionAlgos(typedExt.Algorithms),
		}

	case *utls.FakeTokenBindingExtension:
		return &utls.FakeTokenBindingExtension{
			MajorVersion:  typedExt.MajorVersion,
			MinorVersion:  typedExt.MinorVersion,
			KeyParameters: cloneUint8Slice(typedExt.KeyParameters),
		}

	case *utls.FakeRecordSizeLimitExtension:
		return &utls.FakeRecordSizeLimitExtension{
			Limit: typedExt.Limit,
		}

	case *utls.FakeDelegatedCredentialsExtension:
		return &utls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: cloneSignatureSchemes(typedExt.SupportedSignatureAlgorithms),
		}

	case *utls.FakeChannelIDExtension:
		return &utls.FakeChannelIDExtension{
			OldExtensionID: typedExt.OldExtensionID,
		}

	default:
		return nil
	}
}

// Helper functions to deep clone different data types
func cloneStringSlice(src []string) []string {
	if src == nil {
		return nil
	}
	dest := make([]string, len(src))
	copy(dest, src)
	return dest
}

func cloneCurveIDs(src []utls.CurveID) []utls.CurveID {
	if src == nil {
		return nil
	}
	dest := make([]utls.CurveID, len(src))
	copy(dest, src)
	return dest
}

func cloneUint8Slice(src []uint8) []uint8 {
	if src == nil {
		return nil
	}
	dest := make([]uint8, len(src))
	copy(dest, src)
	return dest
}

func cloneSignatureSchemes(src []utls.SignatureScheme) []utls.SignatureScheme {
	if src == nil {
		return nil
	}
	dest := make([]utls.SignatureScheme, len(src))
	copy(dest, src)
	return dest
}

func cloneKeyShares(src []utls.KeyShare) []utls.KeyShare {
	if src == nil {
		return nil
	}
	dest := make([]utls.KeyShare, len(src))
	copy(dest, src)
	return dest
}

func cloneUint16Slice(src []uint16) []uint16 {
	if src == nil {
		return nil
	}
	dest := make([]uint16, len(src))
	copy(dest, src)
	return dest
}

func cloneByteSlice(src []byte) []byte {
	if src == nil {
		return nil
	}
	dest := make([]byte, len(src))
	copy(dest, src)
	return dest
}

func cloneCertCompressionAlgos(src []utls.CertCompressionAlgo) []utls.CertCompressionAlgo {
	if src == nil {
		return nil
	}
	dest := make([]utls.CertCompressionAlgo, len(src))
	copy(dest, src)
	return dest
}
*/
