package nms

// registry.go — connector assembly + registry. Each vendor Connector bundles its
// spec + auth + poller + webhook + transformer. Adding a vendor is one entry
// here; the runtime and the rest of the system stay connector-agnostic.

// connector is the concrete Connector implementation (a struct of the parts).
type connector struct {
	spec        ConnectorSpec
	auth        AuthProvider
	poller      Poller
	webhook     WebhookHandler
	transformer Transformer
}

func (c connector) Spec() ConnectorSpec      { return c.spec }
func (c connector) Auth() AuthProvider       { return c.auth }
func (c connector) Poller() Poller           { return c.poller }
func (c connector) Webhook() WebhookHandler  { return c.webhook }
func (c connector) Transformer() Transformer { return c.transformer }

// Registry maps vendor → Connector.
type Registry struct {
	connectors map[string]Connector
}

// NewRegistry assembles every built-in connector.
func NewRegistry() *Registry {
	specs := Specs()
	r := &Registry{connectors: map[string]Connector{}}
	reg := func(vendor string, auth AuthProvider, poller Poller, wh WebhookHandler, tr Transformer) {
		r.connectors[vendor] = connector{spec: specs[vendor], auth: auth, poller: poller, webhook: wh, transformer: tr}
	}
	reg("meraki", MerakiAuth{}, merakiPoller(), MerakiWebhook{}, MerakiTransformer{})
	reg("catalyst_center", CatalystAuth{}, catalystPoller(), nil, CatalystTransformer{})
	// catalyst_9800 is the WIRELESS WLC source (#128) — RESTCONF oper/cfg data,
	// distinct from catalyst_center's assurance issues.
	reg("catalyst_9800", Catalyst9800Auth{}, catalyst9800Poller(), nil, Catalyst9800Transformer{})
	// vmanage uses the shape-routing transformer so BOTH lanes work through the
	// single Transformer seam: alarms → events/states, approute → metrics.
	reg("vmanage", VManageAuth{}, vmanagePoller(), nil, VManageAutoTransformer{})
	reg("ndfc", NDFCAuth{}, ndfcPoller(), nil, NDFCTransformer{})
	reg("prime", PrimeAuth{}, primePoller(), nil, PrimeTransformer{})
	reg("versa_director", VersaAuth{}, versaPoller(), nil, VersaDirectorTransformer{})
	reg("versa_concerto", VersaAuth{}, versaPoller(), nil, VersaConcertoTransformer{})
	reg("generic", GenericAuth{}, genericPoller(), GenericWebhook{}, GenericTransformer{})
	return r
}

// Get returns the connector for a vendor.
func (r *Registry) Get(vendor string) (Connector, bool) {
	c, ok := r.connectors[vendor]
	return c, ok
}

// Vendors lists the registered vendors.
func (r *Registry) Vendors() []string {
	out := make([]string, 0, len(r.connectors))
	for v := range r.connectors {
		out = append(out, v)
	}
	return out
}
