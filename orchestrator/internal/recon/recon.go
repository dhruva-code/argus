// Package recon implements the Milestone 2 discovery pipeline: passive
// subdomain enumeration, active resolution + bruteforce, and merge / resolve /
// alive-host detection. It normalizes every discovery into an Asset with source
// attribution and a scope decision, and emits assets and edges incrementally so
// the gateway's Asset Identity Engine can upsert them live.
//
// Every actively-probed host is checked against the project scope AND the SSRF
// guard before a request is made. Passive enumeration may surface out-of-scope
// hosts; they are recorded (tagged out-of-scope) but never probed.
package recon

// AssetType values (mirror app.models.AssetType).
const (
	TypeDomain    = "domain"
	TypeSubdomain = "subdomain"
	TypeIP        = "ip"
	TypeURL       = "url"
	TypeASN       = "asn"
	TypeNetblock  = "netblock"
)

// Status values (mirror app.models.AssetStatus).
const (
	StatusUnknown  = "unknown"
	StatusResolved = "resolved"
	StatusAlive    = "alive"
	StatusDead     = "dead"
)

// Edge kinds (mirror app.models.EdgeKind).
const (
	EdgeResolvesTo  = "resolves_to"
	EdgeCnameTo     = "cname_to"
	EdgeRedirectsTo = "redirects_to"
	EdgeHosts       = "hosts"
	EdgeBelongsTo   = "belongs_to"
	EdgeAnnouncedBy = "announced_by"
	EdgeServes      = "serves"
)

// Phase keys (mirror app.seed_profiles.ALL_PHASES).
const (
	PhasePassiveEnum = "passive_subdomain_enum"
	PhaseActiveEnum  = "active_subdomain_enum"
	PhaseMergeAlive  = "merge_resolve_alive"
	// PhaseInfraMap (infra.go), PhaseVHost (vhost.go), PhaseEndpoints (endpoints.go)
	// PhaseJSAnalysis (jsanalysis.go), PhaseDirDiscovery (dirdiscovery.go),
	// PhaseSourceIntel (github.go), PhasePortScan (ports.go), PhaseVulnScan (vulnscan.go)
)

// Asset is a normalized discovery. Zero-valued fields are simply not reported;
// the gateway merges partial updates into the stored row.
type Asset struct {
	Type         string   `json:"type"`
	Value        string   `json:"value"`
	InScope      bool     `json:"in_scope"`
	ScopeReason  string   `json:"scope_reason"`
	Status       string   `json:"status"`
	Sources      []string `json:"sources"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	CNAME        string   `json:"cname,omitempty"`
	IsWildcard   bool     `json:"is_wildcard,omitempty"`
	HTTPStatus   int      `json:"http_status,omitempty"`
	HTTPTitle    string   `json:"http_title,omitempty"`
	HTTPServer   string   `json:"http_server,omitempty"`
	HTTPScheme   string   `json:"http_scheme,omitempty"`
	HTTPPort     int      `json:"http_port,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	FinalURL     string   `json:"final_url,omitempty"`
	TLSNames     []string `json:"tls_names,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	// Infra carries Phase-3 enrichment (asn, asn_org, netblock, geo_country,
	// ptr, cloud_provider) as string key/values the gateway maps to columns.
	Infra map[string]string `json:"infra,omitempty"`
}

// Edge is a relationship between two assets, addressed by value (the gateway
// resolves/creates both endpoints).
type Edge struct {
	SrcType  string `json:"src_type"`
	SrcValue string `json:"src_value"`
	DstType  string `json:"dst_type"`
	DstValue string `json:"dst_value"`
	Kind     string `json:"kind"`
}

// Callbacks are how the pipeline reports progress. All are safe to call from a
// single goroutine (the pipeline is sequential).
type Callbacks struct {
	Log        func(level, msg string)
	Asset      func(Asset)
	Edge       func(Edge)
	VHost      func(VHost)
	Endpoint   func(Endpoint)
	Secret     func(Secret)
	Repo       func(Repository)
	Port       func(Port)
	Finding    func(Finding)
	InjPoint   func(InjPointRecord)
	Checkpoint func(phase string, data map[string]any)
	Cancelled  func() bool
}

func (c Callbacks) emitInjPoint(p InjPointRecord) {
	if c.InjPoint != nil {
		c.InjPoint(p)
	}
}

func (c Callbacks) emitPort(p Port) {
	if c.Port != nil {
		c.Port(p)
	}
}

func (c Callbacks) emitFinding(f Finding) {
	if c.Finding != nil {
		c.Finding(f)
	}
}

func (c Callbacks) emitVHost(v VHost) {
	if c.VHost != nil {
		c.VHost(v)
	}
}

func (c Callbacks) emitEndpoint(e Endpoint) {
	if c.Endpoint != nil {
		c.Endpoint(e)
	}
}

func (c Callbacks) emitSecret(s Secret) {
	if c.Secret != nil {
		c.Secret(s)
	}
}

func (c Callbacks) emitRepo(r Repository) {
	if c.Repo != nil {
		c.Repo(r)
	}
}

func (c Callbacks) log(level, msg string) {
	if c.Log != nil {
		c.Log(level, msg)
	}
}

func (c Callbacks) cancelled() bool { return c.Cancelled != nil && c.Cancelled() }
