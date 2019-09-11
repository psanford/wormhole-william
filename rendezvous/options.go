package rendezvous

type ClientOption interface {
	setValue(*Client)
}

type versionOption struct {
	agentString  string
	agentVersion string
}

func (o *versionOption) setValue(c *Client) {
	c.agentString = o.agentString
	c.agentVersion = o.agentVersion
}

// WithVersion returns a ClientOption to override the default client
// identifier and version reported to the rendezvous server.
func WithVersion(agentID string, version string) ClientOption {
	return &versionOption{
		agentString:  agentID,
		agentVersion: version,
	}
}
