package tests

type PeetResponse struct {
	IP          string `json:"ip"`
	HTTPVersion string `json:"http_version"`
	Method      string `json:"method"`
	UserAgent   string `json:"user_agent"`
	TLS         TLS    `json:"tls"`
	Http2       *Http2 `json:"http2,omitempty"`
	Http1       *Http1 `json:"http1,omitempty"`
	Tcpip       *Tcpip `json:"tcpip"`
}

type Http2 struct {
	AkamaiFingerprint     string   `json:"akamai_fingerprint"`
	AkamaiFingerprintHash string   `json:"akamai_fingerprint_hash"`
	SentFrames            []*Frame `json:"sent_frames"`
}

type Http1 struct {
	Headers []string `json:"headers"`
}

type Frame struct {
	FrameType string   `json:"frame_type"`
	Length    int64    `json:"length"`
	Settings  []string `json:"settings,omitempty"`
	Increment int64    `json:"increment,omitempty"`
	StreamID  int64    `json:"stream_id,omitempty"`
	Headers   []string `json:"headers,omitempty"`
	Flags     []string `json:"flags,omitempty"`
	Priority  Priority `json:"priority,omitempty"`
}

type Priority struct {
	Weight    int64 `json:"weight"`
	DependsOn int64 `json:"depends_on"`
	Exclusive int64 `json:"exclusive"`
}

type TLS struct {
	Ciphers              []string    `json:"ciphers"`
	Extensions           []Extension `json:"extensions"`
	TLSVersionRecord     string      `json:"tls_version_record"`
	TLSVersionNegotiated string      `json:"tls_version_negotiated"`
	Ja3                  string      `json:"ja3"`
	Ja3Hash              string      `json:"ja3_hash"`
	Ja4                  string      `json:"ja4"`
	Peetprint            string      `json:"peetprint"`
	PeetprintHash        string      `json:"peetprint_hash"`
	ClientRandom         string      `json:"client_random"`
	SessionID            string      `json:"session_id"`
}

type Extension struct {
	Name                       string              `json:"name"`
	Protocols                  []string            `json:"protocols,omitempty"`
	SharedKeys                 []map[string]string `json:"shared_keys,omitempty"`
	Data                       string              `json:"data,omitempty"`
	SignatureAlgorithms        []string            `json:"signature_algorithms,omitempty"`
	MasterSecretData           string              `json:"master_secret_data,omitempty"`
	ExtendedMasterSecretData   string              `json:"extended_master_secret_data,omitempty"`
	StatusRequest              *StatusRequest      `json:"status_request,omitempty"`
	SupportedGroups            []string            `json:"supported_groups,omitempty"`
	Algorithms                 []string            `json:"algorithms,omitempty"`
	EllipticCurvesPointFormats []string            `json:"elliptic_curves_point_formats,omitempty"`
	Versions                   []string            `json:"versions,omitempty"`
	PSKKeyExchangeMode         string              `json:"PSK_Key_Exchange_Mode,omitempty"`
	ServerName                 string              `json:"server_name,omitempty"`
	SignatureHashAlgorithms    []string            `json:"signature_hash_algorithms,omitempty"`
}

type StatusRequest struct {
	CertificateStatusType   string `json:"certificate_status_type"`
	ResponderIDListLength   int64  `json:"responder_id_list_length"`
	RequestExtensionsLength int64  `json:"request_extensions_length"`
}

type Tcpip struct {
	CapLength int64 `json:"cap_length"`
	DstPort   int64 `json:"dst_port"`
	SrcPort   int64 `json:"src_port"`
	IP        IP    `json:"ip"`
	TCP       TCP   `json:"tcp"`
}

type IP struct {
	ID        int64  `json:"id"`
	TTL       int64  `json:"ttl"`
	IPVersion int64  `json:"ip_version"`
	DstIP     string `json:"dst_ip"`
	SrcIP     string `json:"src_ip"`
}

type TCP struct {
	ACK      int64 `json:"ack"`
	Checksum int64 `json:"checksum"`
	Seq      int64 `json:"seq"`
	Window   int64 `json:"window"`
}
