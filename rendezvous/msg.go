package rendezvous

// Server sent wecome message
type WelcomeMsg struct {
	Type     string                 `json:"type" rendezvous_value:"welcome"`
	Welcome  map[string]interface{} `json:"welcome"`
	ServerTX float64                `json:"server_tx"`
}

// Client sent bind message
type BindMsg struct {
	Type  string `json:"type" rendezvous_value:"bind"`
	Side  string `json:"side"`
	AppID string `json:"appid"`
	ID    string `json:"id"`
}

// Client sent aollocate message
type AllocateMsg struct {
	Type string `json:"type" rendezvous_value:"allocate"`
	ID   string `json:"id"`
}

// Server sent ack message
type AckMsg struct {
	Type     string  `json:"type" rendezvous_value:"ack"`
	ID       string  `json:"id"`
	ServerTX float64 `json:"server_tx"`
}

// Server sent allocated message
type AllocatedRespMsg struct {
	Type      string  `json:"type" rendezvous_value:"allocated"`
	Nameplate string  `json:"nameplate"`
	ServerTX  float64 `json:"server_tx"`
}

// Client sent claim message
type ClaimMsg struct {
	Type      string `json:"type" rendezvous_value:"claim"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

// Server sent claimed message
type ClaimedRespMsg struct {
	Type     string  `json:"type" rendezvous_value:"claimed"`
	Mailbox  string  `json:"mailbox"`
	ServerTX float64 `json:"server_tx"`
}

// Client sent open message
type OpenMsg struct {
	Type    string `json:"type" rendezvous_value:"open"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
}

// Client sent add message
type AddMsg struct {
	Type  string `json:"type" rendezvous_value:"add"`
	ID    string `json:"id"`
	Phase string `json:"phase"`
	// Body is a hex string encoded json submessage
	Body string `json:"body"`
}

// Server sent message message
type MessageMsg struct {
	Type  string `json:"type" rendezvous_value:"add"`
	ID    string `json:"id"`
	Side  string `json:"side"`
	Phase string `json:"phase"`
	// Body is a hex string encoded json submessage
	Body     string  `json:"body"`
	ServerRX float64 `json:"server_rx"`
	ServerTX float64 `json:"server_tx"`
}
