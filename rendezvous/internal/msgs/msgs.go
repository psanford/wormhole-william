package msgs

// Server sent wecome message
type Welcome struct {
	Type     string            `json:"type" rendezvous_value:"welcome"`
	Welcome  WelcomeServerInfo `json:"welcome"`
	ServerTX float64           `json:"server_tx"`
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

// Client sent aollocate message
type Allocate struct {
	Type string `json:"type" rendezvous_value:"allocate"`
	ID   string `json:"id"`
}

// Server sent ack message
type Ack struct {
	Type     string  `json:"type" rendezvous_value:"ack"`
	ID       string  `json:"id"`
	ServerTX float64 `json:"server_tx"`
}

// Server sent allocated message
type AllocatedResp struct {
	Type      string  `json:"type" rendezvous_value:"allocated"`
	Nameplate string  `json:"nameplate"`
	ServerTX  float64 `json:"server_tx"`
}

// Client sent claim message
type Claim struct {
	Type      string `json:"type" rendezvous_value:"claim"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

// Server sent claimed message
type ClaimedResp struct {
	Type     string  `json:"type" rendezvous_value:"claimed"`
	Mailbox  string  `json:"mailbox"`
	ServerTX float64 `json:"server_tx"`
}

// Client sent open message
type Open struct {
	Type    string `json:"type" rendezvous_value:"open"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
}

// Client sent add message to add a message to a mailbox.
type Add struct {
	Type  string `json:"type" rendezvous_value:"add"`
	ID    string `json:"id"`
	Phase string `json:"phase"`
	// Body is a hex string encoded json submessage
	Body string `json:"body"`
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

// Client sent list message to list nameplates.
type List struct {
	Type string `json:"type" rendezvous_value:"list"`
	ID   string `json:"id"`
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

// Client sent release message to release a nameplate.
type Release struct {
	Type      string `json:"type" rendezvous_value:"release"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

// Server sent response to release request.
type ReleasedResp struct {
	Type     string  `json:"type" rendezvous_value:"released"`
	ServerTX float64 `json:"server_tx"`
}

// Server sent error message
type Error struct {
	Type     string      `json:"type" rendezvous_value:"error"`
	Error    string      `json:"error"`
	Orig     interface{} `json:"orig"`
	ServerTx float64     `json:"server_tx"`
}

type Close struct {
	Type    string `json:"type" rendezvous_value:"close"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
	Mood    string `json:"mood"`
}

type ClosedResp struct {
	Type     string  `json:"type" rendezvous_value:"closed"`
	ServerTx float64 `json:"server_tx"`
}

type GenericServerMsg struct {
	Type     string  `json:"type"`
	ServerTX float64 `json:"server_tx"`
	ID       string  `json:"id"`
	Error    string  `json:"error"`
}

var MsgMap = map[string]interface{}{
	"welcome":    Welcome{},
	"bind":       Bind{},
	"allocate":   Allocate{},
	"ack":        Ack{},
	"allocated":  AllocatedResp{},
	"claim":      Claim{},
	"claimed":    ClaimedResp{},
	"open":       Open{},
	"add":        Add{},
	"message":    Message{},
	"list":       List{},
	"nameplates": Nameplates{},
	"release":    Release{},
	"released":   ReleasedResp{},
	"error":      Error{},
	"close":      Close{},
	"closed":     ClosedResp{},
}
