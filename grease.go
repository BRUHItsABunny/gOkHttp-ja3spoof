package gokhttp_ja3spoof

import (
	"strings"

	device_utils "github.com/BRUHItsABunny/go-device-utils"
)

// greasePrefix is how peet.ws labels a GREASE value, e.g. "TLS_GREASE (0x3a3a)".
const greasePrefix = "TLS_GREASE"

// TLSGREASEConfig records where a browser places GREASE values in its ClientHello.
//
// device_utils.Browser_TLSFingerprint cannot carry this: FromPEET skips every GREASE entry it
// parses and the generated enums have no GREASE member. Chrome brackets its extension list
// with GREASE and seeds four more lists with it, Firefox uses none at all, so the positions
// have to be read off the raw PEET response instead of guessed from the fingerprint.
type TLSGREASEConfig struct {
	// CipherSuites puts a GREASE placeholder in front of the cipher suites.
	CipherSuites bool
	// SupportedGroups puts a GREASE placeholder in front of the supported_groups (10) curves.
	SupportedGroups bool
	// SupportedVersions puts a GREASE placeholder in front of supported_versions (43).
	SupportedVersions bool
	// KeyShare puts a GREASE key share in front of key_share (51).
	KeyShare bool
	// LeadingExtension sends a GREASE extension as the first extension.
	LeadingExtension bool
	// TrailingExtension sends a GREASE extension as the last extension.
	TrailingExtension bool
}

// DefaultTLSGREASEConfig is the GREASE layout used when none was extracted. It seeds the four
// value lists, matching DefaultExtensionMapV2 and CreateSpecWithJA3Str, but sends no GREASE
// extensions: those change the extension count and would be wrong for browsers that do not
// GREASE at all.
func DefaultTLSGREASEConfig() *TLSGREASEConfig {
	return &TLSGREASEConfig{
		CipherSuites:      true,
		SupportedGroups:   true,
		SupportedVersions: true,
		KeyShare:          true,
	}
}

// ExtractGREASEFromPEET reads the GREASE layout off a raw PEET response, before FromPEET
// discards it. Pair it with CreateSpecWithTLSFingerprintAndGREASE to reproduce the extension
// bracketing that a fingerprint alone cannot describe.
func ExtractGREASEFromPEET(response *device_utils.PeetResponse) *TLSGREASEConfig {
	if response == nil {
		return &TLSGREASEConfig{}
	}
	tlsData := response.TLS
	grease := &TLSGREASEConfig{
		CipherSuites: isGREASEName(firstString(tlsData.Ciphers)),
	}

	if len(tlsData.Extensions) > 0 {
		grease.LeadingExtension = isGREASEName(tlsData.Extensions[0].Name)
		grease.TrailingExtension = isGREASEName(tlsData.Extensions[len(tlsData.Extensions)-1].Name)
	}

	for _, extension := range tlsData.Extensions {
		switch {
		case len(extension.SupportedGroups) > 0:
			grease.SupportedGroups = isGREASEName(firstString(extension.SupportedGroups))
		case len(extension.Versions) > 0:
			grease.SupportedVersions = isGREASEName(firstString(extension.Versions))
		case len(extension.SharedKeys) > 0:
			for name := range extension.SharedKeys[0] {
				if isGREASEName(name) {
					grease.KeyShare = true
				}
			}
		}
	}

	return grease
}

func isGREASEName(name string) bool {
	return strings.HasPrefix(name, greasePrefix)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
