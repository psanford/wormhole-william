package msgs

import "github.com/psanford/wormhole-william/internal/crypto"

func NewWelcome() *Welcome {
	return &Welcome{
		Type: "welcome",
	}
}

// Server sent wecome message
type Welcome struct {
	Type     string            `json:"type" rendezvous_value:"welcome"`
	Welcome  WelcomeServerInfo `json:"welcome"`
	ServerTX float64           `json:"server_tx"`
}

func (w *Welcome) GetType() string {
	return w.Type
}

type WelcomeServerInfo struct {
	MOTD              string `json:"motd"`
	CurrentCLIVersion string `json:"current_cli_version"`
	Error             string `json:"error"`
}

func NewBind(side, appid string, clientVersion []string) *Bind {
	return &Bind{
		Type:          "bind",
		ID:            crypto.RandHex(2),
		Side:          side,
		AppID:         appid,
		ClientVersion: clientVersion,
	}
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

func (b *Bind) GetType() string {
	return b.Type
}

func (b *Bind) GetID() string {
	return b.ID
}

func NewAllocate() *Allocate {
	return &Allocate{
		Type: "allocate",
		ID:   crypto.RandHex(2),
	}
}

// Client sent aollocate message
type Allocate struct {
	Type string `json:"type" rendezvous_value:"allocate"`
	ID   string `json:"id"`
}

func (a *Allocate) GetType() string {
	return a.Type
}

func (a *Allocate) GetID() string {
	return a.ID
}

func NewAck() *Ack {
	return &Ack{
		Type: "ack",
		ID:   crypto.RandHex(2),
	}
}

// Server sent ack message
type Ack struct {
	Type     string  `json:"type" rendezvous_value:"ack"`
	ID       string  `json:"id"`
	ServerTX float64 `json:"server_tx"`
}

func (a *Ack) GetType() string {
	return a.Type
}

func (a *Ack) GetID() string {
	return a.ID
}

func NewAllocatedResp() *AllocatedResp {
	return &AllocatedResp{
		Type: "allocated",
	}
}

// Server sent allocated message
type AllocatedResp struct {
	Type      string  `json:"type" rendezvous_value:"allocated"`
	Nameplate string  `json:"nameplate"`
	ServerTX  float64 `json:"server_tx"`
}

func (a *AllocatedResp) GetType() string {
	return a.Type
}

func NewClaim(nameplate string) *Claim {
	return &Claim{
		Type:      "claim",
		ID:        crypto.RandHex(2),
		Nameplate: nameplate,
	}
}

// Client sent claim message
type Claim struct {
	Type      string `json:"type" rendezvous_value:"claim"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

func (c *Claim) GetType() string {
	return c.Type
}

func (c *Claim) GetID() string {
	return c.ID
}

func NewClaimedResp() *ClaimedResp {
	return &ClaimedResp{
		Type: "claimed",
	}
}

// Server sent claimed message
type ClaimedResp struct {
	Type     string  `json:"type" rendezvous_value:"claimed"`
	Mailbox  string  `json:"mailbox"`
	ServerTX float64 `json:"server_tx"`
}

func (c *ClaimedResp) GetType() string {
	return c.Type
}

func NewOpen(mailbox string) *Open {
	return &Open{
		Type:    "open",
		ID:      crypto.RandHex(2),
		Mailbox: mailbox,
	}
}

// Client sent open message
type Open struct {
	Type    string `json:"type" rendezvous_value:"open"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
}

func (o *Open) GetType() string {
	return o.Type
}

func (o *Open) GetID() string {
	return o.ID
}

func NewAdd(phase, body string) *Add {
	return &Add{
		Type:  "add",
		ID:    crypto.RandHex(2),
		Phase: phase,
		Body:  body,
	}
}

// Client sent add message to add a message to a mailbox.
type Add struct {
	Type  string `json:"type" rendezvous_value:"add"`
	ID    string `json:"id"`
	Phase string `json:"phase"`
	// Body is a hex string encoded json submessage
	Body string `json:"body"`
}

func (a *Add) GetType() string {
	return a.Type
}

func (a *Add) GetID() string {
	return a.ID
}

func NewMessage() *Message {
	return &Message{
		Type: "message",
		ID:   crypto.RandHex(2),
	}
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

func (m *Message) GetType() string {
	return m.Type
}

func (m *Message) GetID() string {
	return m.ID
}

func NewList() *List {
	return &List{
		Type: "list",
		ID:   crypto.RandHex(2),
	}
}

// Client sent list message to list nameplates.
type List struct {
	Type string `json:"type" rendezvous_value:"list"`
	ID   string `json:"id"`
}

func (l *List) GetType() string {
	return l.Type
}

func (l *List) GetID() string {
	return l.ID
}

func NewNameplates() *Nameplates {
	return &Nameplates{
		Type: "nameplates",
	}
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

func (n *Nameplates) GetType() string {
	return n.Type
}

func NewRelease(nameplate string) *Release {
	return &Release{
		Type:      "release",
		ID:        crypto.RandHex(2),
		Nameplate: nameplate,
	}
}

// Client sent release message to release a nameplate.
type Release struct {
	Type      string `json:"type" rendezvous_value:"release"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

func (r *Release) GetType() string {
	return r.Type
}

func (r *Release) GetID() string {
	return r.ID
}

func NewReleasedResp() *ReleasedResp {
	return &ReleasedResp{
		Type: "released",
	}
}

// Server sent response to release request.
type ReleasedResp struct {
	Type     string  `json:"type" rendezvous_value:"released"`
	ServerTX float64 `json:"server_tx"`
}

func (r *ReleasedResp) GetType() string {
	return r.Type
}

func NewError(errorStr string, orig interface{}) *Error {
	return &Error{
		Type:  "error",
		Error: errorStr,
		Orig:  orig,
	}
}

// Server sent error message
type Error struct {
	Type     string      `json:"type" rendezvous_value:"error"`
	Error    string      `json:"error"`
	Orig     interface{} `json:"orig"`
	ServerTx float64     `json:"server_tx"`
}

func (e *Error) GetType() string {
	return e.Type
}

func NewClose(mood, mailbox string) *Close {
	return &Close{
		Type:    "close",
		ID:      crypto.RandHex(2),
		Mood:    mood,
		Mailbox: mailbox,
	}
}

type Close struct {
	Type    string `json:"type" rendezvous_value:"close"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
	Mood    string `json:"mood"`
}

func (c *Close) GetType() string {
	return c.Type
}

func (c *Close) GetID() string {
	return c.ID
}

func NewClosedResp() *ClosedResp {
	return &ClosedResp{
		Type: "closed",
	}
}

type ClosedResp struct {
	Type     string  `json:"type" rendezvous_value:"closed"`
	ServerTx float64 `json:"server_tx"`
}

func (c *ClosedResp) GetType() string {
	return c.Type
}

type GenericServerMsg struct {
	Type     string  `json:"type"`
	ServerTX float64 `json:"server_tx"`
	ID       string  `json:"id"`
	Error    string  `json:"error"`
}

func (g *GenericServerMsg) GetID() string {
	return g.ID
}
