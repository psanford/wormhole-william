package msgs

// Server sent wecome message
type Welcome struct {
	Type     string            `json:"type" rendezvous_value:"welcome"`
	Welcome  WelcomeServerInfo `json:"welcome"`
	ServerTX float64           `json:"server_tx"`
}

func (w *Welcome) RendezvousValue() string {
	return "welcome"
}

type WelcomeServerInfo struct {
	MOTD              string `json:"motd"`
	CurrentCLIVersion string `json:"current_cli_version"`
	Error             string `json:"error"`
}

// Client sent bind message
type Bind struct {
	Type  string `json:"type" rendezvous_value:"bind"`
	ID    string `json:"id"`
	Side  string `json:"side"`
	AppID string `json:"appid"`
	// ClientVersion is by convention a two value array
	// of [client_id, version]
	ClientVersion []string `json:"client_version"`
}

func (b *Bind) RendezvousValue() string {
	return "bind"
}

// Client sent aollocate message
type Allocate struct {
	Type string `json:"type" rendezvous_value:"allocate"`
	ID   string `json:"id"`
}

func (a *Allocate) RendezvousValue() string {
	return "allocate"
}

// Server sent ack message
type Ack struct {
	Type     string  `json:"type" rendezvous_value:"ack"`
	ID       string  `json:"id"`
	ServerTX float64 `json:"server_tx"`
}

func (a *Ack) RendezvousValue() string {
	return "ack"
}

// Server sent allocated message
type AllocatedResp struct {
	Type      string  `json:"type" rendezvous_value:"allocated"`
	Nameplate string  `json:"nameplate"`
	ServerTX  float64 `json:"server_tx"`
}

func (a *AllocatedResp) RendezvousValue() string {
	return "allocated"
}

// Client sent claim message
type Claim struct {
	Type      string `json:"type" rendezvous_value:"claim"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

func (c *Claim) RendezvousValue() string {
	return "claim"
}

// Server sent claimed message
type ClaimedResp struct {
	Type     string  `json:"type" rendezvous_value:"claimed"`
	Mailbox  string  `json:"mailbox"`
	ServerTX float64 `json:"server_tx"`
}

func (c *ClaimedResp) RendezvousValue() string {
	return "claimed"
}

// Client sent open message
type Open struct {
	Type    string `json:"type" rendezvous_value:"open"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
}

func (o *Open) RendezvousValue() string {
	return "open"
}

// Client sent add message to add a message to a mailbox.
type Add struct {
	Type  string `json:"type" rendezvous_value:"add"`
	ID    string `json:"id"`
	Phase string `json:"phase"`
	// Body is a hex string encoded json submessage
	Body string `json:"body"`
}

func (a *Add) RendezvousValue() string {
	return "add"
}

// Server sent message message
type Message struct {
	Type  string `json:"type" rendezvous_value:"message"`
	ID    string `json:"id"`
	Side  string `json:"side"`
	Phase string `json:"phase"`
	// Body is a hex string encoded json submessage
	Body     string  `json:"body"`
	ServerRX float64 `json:"server_rx"`
	ServerTX float64 `json:"server_tx"`
}

func (m *Message) RendezvousValue() string {
	return "message"
}

// Client sent list message to list nameplates.
type List struct {
	Type string `json:"type" rendezvous_value:"list"`
	ID   string `json:"id"`
}

func (l *List) RendezvousValue() string {
	return "list"
}

// Server sent nameplates message.
// The server sends this in response to ListMsg.
// It contains the list of active nameplates.
type Nameplates struct {
	Type       string `json:"type" rendezvous_value:"nameplates"`
	Nameplates []struct {
		ID string `json:"id"`
	} `json:"nameplates"`
	ServerTX float64 `json:"server_tx"`
}

func (n *Nameplates) RendezvousValue() string {
	return "nameplates"
}

// Client sent release message to release a nameplate.
type Release struct {
	Type      string `json:"type" rendezvous_value:"release"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

func (r *Release) RendezvousValue() string {
	return "release"
}

// Server sent response to release request.
type ReleasedResp struct {
	Type     string  `json:"type" rendezvous_value:"released"`
	ServerTX float64 `json:"server_tx"`
}

func (r *ReleasedResp) RendezvousValue() string {
	return "released"
}

// Server sent error message
type Error struct {
	Type     string      `json:"type" rendezvous_value:"error"`
	Error    string      `json:"error"`
	Orig     interface{} `json:"orig"`
	ServerTx float64     `json:"server_tx"`
}

func (e *Error) RendezvousValue() string {
	return "error"
}

type Close struct {
	Type    string `json:"type" rendezvous_value:"close"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
	Mood    string `json:"mood"`
}

func (c *Close) RendezvousValue() string {
	return "close"
}

type ClosedResp struct {
	Type     string  `json:"type" rendezvous_value:"closed"`
	ServerTx float64 `json:"server_tx"`
}

func (c *ClosedResp) RendezvousValue() string {
	return "closed"
}

type GenericServerMsg struct {
	Type     string  `json:"type"`
	ServerTX float64 `json:"server_tx"`
	ID       string  `json:"id"`
	Error    string  `json:"error"`
}
