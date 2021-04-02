package rendezvousservertest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous/internal/msgs"
)

type TestServer struct {
	*httptest.Server
	mu         sync.Mutex
	mailboxes  map[string]*mailbox
	nameplates map[int16]string
	agents     [][]string
}

func NewServer() *TestServer {
	ts := &TestServer{
		mailboxes:  make(map[string]*mailbox),
		nameplates: make(map[int16]string),
	}

	smux := http.NewServeMux()
	smux.HandleFunc("/ws", ts.handleWS)

	ts.Server = httptest.NewServer(smux)
	return ts
}

func (ts *TestServer) Agents() [][]string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.agents
}

func (ts *TestServer) WebSocketURL() string {
	u, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)

	}

	u.Scheme = "ws"
	u.Path = "/ws"

	return u.String()

}

type mailbox struct {
	sync.Mutex
	claimCount int
	msgs       []mboxMsg
	clients    map[string]chan mboxMsg
}

func newMailbox() *mailbox {
	return &mailbox{
		msgs:    make([]mboxMsg, 0, 4),
		clients: make(map[string]chan mboxMsg),
	}
}

func (m *mailbox) Add(side string, addMsg *msgs.Add) {
	m.Lock()
	defer m.Unlock()

	msg := mboxMsg{
		side:  side,
		phase: addMsg.Phase,
		body:  addMsg.Body,
	}

	m.msgs = append(m.msgs, msg)

	for side, c := range m.clients {
		select {
		case c <- msg:
		case <-time.After(1 * time.Second):
			log.Printf("Send to %s timed out", side)
		}
	}
}

type mboxMsg struct {
	side  string
	phase string
	body  string
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func prepareServerMsg(msg interface{}) {
	ptr := reflect.TypeOf(msg)

	if ptr.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("msg must be a pointer to a struct, got %T", msg))
	}

	st := ptr.Elem()

	if st.Kind() != reflect.Struct {
		panic(fmt.Sprintf("msg must be a pointer to a struct, got %T", msg))
	}

	val := reflect.ValueOf(msg).Elem()

	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		jsonName := field.Tag.Get("json")
		if jsonName == "type" {
			msgType := field.Tag.Get("rendezvous_value")
			if msgType == "" {
				panic("Type filed missing rendezvous_value struct tag")
			}
			ff := val.Field(i)
			ff.SetString(msgType)
		} else if jsonName == "ServerTX" {
			ff := val.Field(i)
			ff.SetFloat(float64(time.Now().UnixNano()) / float64(time.Second))
		}
	}
}

func serverUnmarshal(m []byte) (interface{}, error) {
	var genericMsg msgs.GenericServerMsg
	err := json.Unmarshal(m, &genericMsg)
	if err != nil {
		return nil, err
	}

	protoType, found := msgs.MsgMap[genericMsg.Type]
	if !found {
		return nil, fmt.Errorf("unknown msg type: %s %v %s", genericMsg.Type, genericMsg, m)
	}
	t := reflect.TypeOf(protoType)
	val := reflect.New(t)
	resultPtr := val.Interface()

	err = json.Unmarshal(m, resultPtr)
	if err != nil {
		return nil, err
	}

	return resultPtr, nil
}

var TestMotd = "ordure-posts"

func (ts *TestServer) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	var sendMu sync.Mutex
	sendMsg := func(msg interface{}) {
		prepareServerMsg(msg)
		sendMu.Lock()
		defer sendMu.Unlock()
		err = c.WriteJSON(msg)
		if err != nil {
			panic(err)
		}
	}

	welcome := &msgs.Welcome{
		Welcome: msgs.WelcomeServerInfo{
			MOTD: TestMotd,
		},
	}
	sendMsg(welcome)

	ackMsg := func(id string) {
		ack := &msgs.Ack{
			ID: id,
		}
		sendMsg(ack)
	}

	errMsg := func(id string, orig interface{}, reason error) {
		errPacket := &msgs.Error{
			Error: reason.Error(),
			Orig:  orig,
		}

		sendMsg(errPacket)
	}

	var sideID string
	var openMailbox *mailbox

	defer func() {
		if sideID != "" && openMailbox != nil {
			openMailbox.Lock()
			delete(openMailbox.clients, sideID)
			openMailbox.Unlock()
		}
	}()

	for {
		_, msgBytes, err := c.ReadMessage()
		if _, isCloseErr := err.(*websocket.CloseError); err == io.EOF || isCloseErr {
			break
		} else if err != nil {
			log.Printf("rendezvousservertest recv err: %s", err)
			break
		}

		msg, err := serverUnmarshal(msgBytes)
		if err != nil {
			panic(fmt.Sprintf("err: %s msg: %s", err, msgBytes))
		}

		switch m := msg.(type) {
		case *msgs.Bind:
			if sideID != "" {
				ackMsg(m.ID)
				errMsg(m.ID, m, fmt.Errorf("already bound"))
				continue
			}

			if m.Side == "" {
				ackMsg(m.ID)
				errMsg(m.ID, m, fmt.Errorf("bind requires 'side'"))
				continue
			}

			ts.mu.Lock()
			ts.agents = append(ts.agents, m.ClientVersion)
			ts.mu.Unlock()
			sideID = m.Side

			ackMsg(m.ID)
		case *msgs.Allocate:
			ackMsg(m.ID)

			var nameplate int16
			ts.mu.Lock()
			for i := int16(1); i < math.MaxInt16; i++ {
				mboxID := ts.nameplates[i]
				if mboxID == "" {
					mboxID = crypto.RandHex(20)

					mbox := newMailbox()

					ts.mailboxes[mboxID] = mbox
					ts.nameplates[i] = mboxID
					nameplate = i
					break
				}
			}
			ts.mu.Unlock()

			if nameplate < 1 {
				errMsg(m.ID, m, fmt.Errorf("failed to allocate nameplate"))
				continue
			}

			resp := &msgs.AllocatedResp{
				Nameplate: fmt.Sprintf("%d", nameplate),
			}
			sendMsg(resp)
		case *msgs.Claim:
			ackMsg(m.ID)

			nameplate, err := strconv.Atoi(m.Nameplate)
			if err != nil {
				panic(fmt.Sprintf("nameplate %s is not an int", m.Nameplate))
			}

			ts.mu.Lock()
			mboxID := ts.nameplates[int16(nameplate)]
			if mboxID == "" {
				mboxID = crypto.RandHex(20)

				mbox := newMailbox()

				ts.mailboxes[mboxID] = mbox
				ts.nameplates[int16(nameplate)] = mboxID
			}
			ts.mu.Unlock()

			ts.mu.Lock()
			mbox := ts.mailboxes[mboxID]
			ts.mu.Unlock()
			if mbox == nil {
				errMsg(m.ID, m, fmt.Errorf("no mailbox found associated to nameplate %s", m.Nameplate))
				continue
			}

			var crowded bool
			mbox.Lock()
			if mbox.claimCount > 1 {
				crowded = true
			} else {
				mbox.claimCount++
			}
			mbox.Unlock()

			if crowded {
				errMsg(m.ID, m, errors.New("crowded"))
				continue
			}

			resp := &msgs.ClaimedResp{
				Mailbox: mboxID,
			}
			sendMsg(resp)
		case *msgs.Open:
			ackMsg(m.ID)

			if openMailbox != nil {
				errMsg(m.ID, m, errors.New("only one open per connection"))
				continue
			}

			ts.mu.Lock()
			mbox := ts.mailboxes[m.Mailbox]
			ts.mu.Unlock()

			if mbox == nil {
				errMsg(m.ID, m, errors.New("mailbox not found"))
				continue
			}

			msgChan := make(chan mboxMsg)

			mbox.Lock()
			mbox.clients[sideID] = msgChan
			pendingMsgs := make([]mboxMsg, len(mbox.msgs))
			copy(pendingMsgs, mbox.msgs)
			mbox.Unlock()

			for _, mboxMsg := range pendingMsgs {
				msg := &msgs.Message{
					Side:  mboxMsg.side,
					Phase: mboxMsg.phase,
					Body:  mboxMsg.body,
				}
				sendMsg(msg)
			}

			go func() {
				for mboxMsg := range msgChan {
					msg := &msgs.Message{
						Side:  mboxMsg.side,
						Phase: mboxMsg.phase,
						Body:  mboxMsg.body,
					}
					sendMsg(msg)
				}
			}()

			openMailbox = mbox
		case *msgs.Release:
			ackMsg(m.ID)

			nameplate, err := strconv.Atoi(m.Nameplate)
			if err != nil {
				errMsg(m.ID, m, errors.New("no nameplate found"))
				continue
			}

			ts.mu.Lock()
			delete(ts.nameplates, int16(nameplate))
			ts.mu.Unlock()

			sendMsg(&msgs.ReleasedResp{})
		case *msgs.Add:
			ackMsg(m.ID)

			openMailbox.Add(sideID, m)

		case *msgs.Close:
			ackMsg(m.ID)

			sendMsg(&msgs.ClosedResp{})

		case *msgs.List:
			ackMsg(m.ID)

			var resp msgs.Nameplates

			ts.mu.Lock()
			for n := range ts.nameplates {
				resp.Nameplates = append(resp.Nameplates, struct {
					ID string `json:"id"`
				}{
					strconv.Itoa(int(n)),
				})
			}
			ts.mu.Unlock()

			sendMsg(&resp)

		default:
			log.Printf("Test server got unexpected message: %v", msg)
		}
	}
}
