package rendezvous

import (
	"crypto/rand"
	"fmt"
	"io"
)

// Server sent wecome message
type welcomeMsg struct {
	Type     string            `json:"type" rendezvous_value:"welcome"`
	Welcome  welcomeServerInfo `json:"welcome"`
	ServerTX float64           `json:"server_tx"`
}

type welcomeServerInfo struct {
	MOTD              string `json:"motd"`
	CurrentCLIVersion string `json:"current_cli_version"`
	Error             string `json:"error"`
}

// Client sent bind message
type bindMsg struct {
	Type  string `json:"type" rendezvous_value:"bind"`
	ID    string `json:"id"`
	Side  string `json:"side"`
	AppID string `json:"appid"`
}

// Client sent aollocate message
type allocateMsg struct {
	Type string `json:"type" rendezvous_value:"allocate"`
	ID   string `json:"id"`
}

// Server sent ack message
type ackMsg struct {
	Type     string  `json:"type" rendezvous_value:"ack"`
	ID       string  `json:"id"`
	ServerTX float64 `json:"server_tx"`
}

// Server sent allocated message
type allocatedRespMsg struct {
	Type      string  `json:"type" rendezvous_value:"allocated"`
	Nameplate string  `json:"nameplate"`
	ServerTX  float64 `json:"server_tx"`
}

// Client sent claim message
type claimMsg struct {
	Type      string `json:"type" rendezvous_value:"claim"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

// Server sent claimed message
type claimedRespMsg struct {
	Type     string  `json:"type" rendezvous_value:"claimed"`
	Mailbox  string  `json:"mailbox"`
	ServerTX float64 `json:"server_tx"`
}

// Client sent open message
type openMsg struct {
	Type    string `json:"type" rendezvous_value:"open"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
}

// Client sent add message to add a message to a mailbox.
type addMsg struct {
	Type  string `json:"type" rendezvous_value:"add"`
	ID    string `json:"id"`
	Phase string `json:"phase"`
	// Body is a hex string encoded json submessage
	Body string `json:"body"`
}

// Server sent message message
type messageMsg struct {
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
type listMsg struct {
	Type string `json:"type" rendezvous_value:"list"`
	ID   string `json:"id"`
}

// Server sent nameplates message.
// The server sends this in response to ListMsg.
// It contains the list of active nameplates.
type nameplatesMsg struct {
	Type       string `json:"type" rendezvous_value:"nameplates"`
	Nameplates []struct {
		ID string `json:"id"`
	} `json:"nameplates"`
	ServerTX float64 `json:"server_tx"`
}

// Client sent release message to release a nameplate.
type releaseMsg struct {
	Type      string `json:"type" rendezvous_value:"release"`
	ID        string `json:"id"`
	Nameplate string `json:"nameplate"`
}

// Server sent response to release request.
type releasedRespMsg struct {
	Type     string  `json:"type" rendezvous_value:"released"`
	ServerTX float64 `json:"server_tx"`
}

// Server sent error message
type errorMsg struct {
	Type     string      `json:"type" rendezvous_value:"error"`
	Error    string      `json:"error"`
	Orig     interface{} `json:"orig"`
	ServerTx float64     `json:"server_tx"`
}

type closeMsg struct {
	Type    string `json:"type" rendezvous_value:"close"`
	ID      string `json:"id"`
	Mailbox string `json:"mailbox"`
	Mood    string `json:"mood"`
}

type closedRespMsg struct {
	Type     string  `json:"type" rendezvous_value:"closed"`
	ServerTx float64 `json:"server_tx"`
}

type genericServerMsg struct {
	Type     string  `json:"type"`
	ServerTX float64 `json:"server_tx"`
	ID       string  `json:"id"`
	Error    string  `json:"error"`
}

var msgMap = map[string]interface{}{
	"welcome":    welcomeMsg{},
	"bind":       bindMsg{},
	"allocate":   allocateMsg{},
	"ack":        ackMsg{},
	"allocated":  allocatedRespMsg{},
	"claim":      claimMsg{},
	"claimed":    claimedRespMsg{},
	"open":       openMsg{},
	"add":        addMsg{},
	"message":    messageMsg{},
	"list":       listMsg{},
	"nameplates": nameplatesMsg{},
	"release":    releaseMsg{},
	"released":   releasedRespMsg{},
	"error":      errorMsg{},
	"close":      closeMsg{},
	"closed":     closedRespMsg{},
}

func randHex(n int) string {
	buf := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("%x", buf)
}
