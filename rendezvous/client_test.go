package rendezvous

import (
	"context"
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
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/psanford/wormhole-william/random"
)

func TestBasicClient(t *testing.T) {
	ts := newServer()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	u.Scheme = "ws"
	u.Path = "/ws"

	side0 := random.SideID()
	side1 := random.SideID()
	appID := "superlatively-abbeys"

	c0 := NewClient(u.String(), side0, appID)

	ctx := context.Background()

	info, err := c0.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if info.MOTD != testMotd {
		t.Fatalf("MOTD got=%s expected=%s", info.MOTD, testMotd)
	}

	nameplate, err := c0.CreateMailbox(ctx)
	if err != nil {
		t.Fatal(err)
	}

	c1 := NewClient(u.String(), side1, appID)
	_, err = c1.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = c1.AttachMailbox(ctx, nameplate)
	if err != nil {
		t.Fatal(err)
	}

	phase0 := "seacoasts-demonstrator"
	body0 := "Roquefort-Gilligan"

	err = c0.AddMessage(ctx, phase0, body0)
	if err != nil {
		t.Fatal(err)
	}

	c0Msgs := c0.MsgChan(ctx)
	c1Msgs := c1.MsgChan(ctx)

	msg := <-c1Msgs

	expectMsg := MailboxEvent{
		Side:  side0,
		Phase: phase0,
		Body:  body0,
	}

	if !reflect.DeepEqual(expectMsg, msg) {
		t.Fatalf("Message mismatch got=%+v, expect=%+v", msg, expectMsg)
	}

	select {
	case m := <-c0Msgs:
		t.Fatalf("c0 got message when it wasn't expecting one: %+v", m)
	default:
	}

	phase1 := "fundamentalists-potluck"
	body1 := "sanitarium-seasonings"
	err = c1.AddMessage(ctx, phase1, body1)
	if err != nil {
		t.Fatal(err)
	}

	msg = <-c0Msgs

	expectMsg = MailboxEvent{
		Side:  side1,
		Phase: phase1,
		Body:  body1,
	}

	if !reflect.DeepEqual(expectMsg, msg) {
		t.Fatalf("Message mismatch got=%+v, expect=%+v", msg, expectMsg)
	}

	select {
	case m := <-c1Msgs:
		t.Fatalf("c1 got message when it wasn't expecting one: %+v", m)
	default:
	}
}

type testServer struct {
	*httptest.Server
	mu         sync.Mutex
	mailboxes  map[string]*mailbox
	nameplates map[int16]string
}

func newServer() *testServer {
	ts := &testServer{
		mailboxes:  make(map[string]*mailbox),
		nameplates: make(map[int16]string),
	}

	smux := http.NewServeMux()
	smux.HandleFunc("/ws", ts.handleWS)

	ts.Server = httptest.NewServer(smux)
	return ts
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

func (m *mailbox) Add(side string, addMsg *addMsg) {
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
		panic("msg must be a pointer")
	}

	st := ptr.Elem()
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

func serverUnmarshal(msg []byte) (interface{}, error) {
	var genericMsg genericServerMsg
	err := json.Unmarshal(msg, &genericMsg)
	if err != nil {
		return nil, err
	}

	protoType, found := msgMap[genericMsg.Type]
	if !found {
		return nil, fmt.Errorf("Unknown msg type: %s %v %s\n", genericMsg.Type, genericMsg, msg)
	}
	t := reflect.TypeOf(protoType)
	val := reflect.New(t)
	resultPtr := val.Interface()

	err = json.Unmarshal(msg, resultPtr)
	if err != nil {
		return nil, err
	}

	return resultPtr, nil
}

var testMotd = "ordure-posts"

func (ts *testServer) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	sendMsg := func(msg interface{}) {
		prepareServerMsg(msg)
		err = c.WriteJSON(msg)
		if err != nil {
			panic(err)
		}
	}

	welcome := &welcomeMsg{
		Welcome: welcomeServerInfo{
			MOTD: "ordure-posts",
		},
	}
	sendMsg(welcome)

	ackMsg := func(id string) {
		ack := &ackMsg{
			ID: id,
		}
		sendMsg(ack)
	}

	errMsg := func(id string, orig interface{}, reason error) {
		errPacket := &errorMsg{
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
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		msg, err := serverUnmarshal(msgBytes)
		if err != nil {
			panic(err)
		}

		switch m := msg.(type) {
		case *bindMsg:
			ackMsg(m.ID)

			if sideID != "" {
				errMsg(m.ID, m, fmt.Errorf("already bound"))
				continue
			}

			if m.Side == "" {
				errMsg(m.ID, m, fmt.Errorf("bind requires 'side'"))
				continue
			}

			sideID = m.Side
		case *allocateMsg:
			ackMsg(m.ID)

			var nameplate int16
			ts.mu.Lock()
			for i := int16(1); i < math.MaxInt16; i++ {
				mboxID := ts.nameplates[i]
				if mboxID == "" {
					mboxID = random.Hex(20)

					mbox := newMailbox()

					ts.mailboxes[mboxID] = mbox
					ts.nameplates[i] = mboxID
					nameplate = i
					break
				}
			}
			ts.mu.Unlock()

			if nameplate < 1 {
				errMsg(m.ID, m, fmt.Errorf("Failed to allocate nameplate"))
				continue
			}

			resp := &allocatedRespMsg{
				Nameplate: fmt.Sprintf("%d", nameplate),
			}
			sendMsg(resp)
		case *claimMsg:
			ackMsg(m.ID)

			nameplate, err := strconv.Atoi(m.Nameplate)
			if err != nil {
				panic(fmt.Sprintf("nameplate %s is not an int", m.Nameplate))
			}

			ts.mu.Lock()
			mboxID := ts.nameplates[int16(nameplate)]
			ts.mu.Unlock()
			if mboxID == "" {
				errMsg(m.ID, m, fmt.Errorf("No namespaces available"))
				continue
			}

			ts.mu.Lock()
			mbox := ts.mailboxes[mboxID]
			ts.mu.Unlock()
			if mbox == nil {
				errMsg(m.ID, m, fmt.Errorf("No mailbox found associated to nameplate %s", m.Nameplate))
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

			resp := &claimedRespMsg{
				Mailbox: mboxID,
			}
			sendMsg(resp)
		case *openMsg:
			ackMsg(m.ID)

			if openMailbox != nil {
				errMsg(m.ID, m, errors.New("opnly one open per conncetion"))
				continue
			}

			ts.mu.Lock()
			mbox := ts.mailboxes[m.Mailbox]
			ts.mu.Unlock()

			if mbox == nil {
				errMsg(m.ID, m, errors.New("Mailbox not found"))
				continue
			}

			msgChan := make(chan mboxMsg)

			mbox.Lock()
			mbox.clients[sideID] = msgChan
			pendingMsgs := make([]mboxMsg, len(mbox.msgs))
			copy(pendingMsgs, mbox.msgs)
			mbox.Unlock()

			for _, mboxMsg := range pendingMsgs {
				msg := &messageMsg{
					Side:  mboxMsg.side,
					Phase: mboxMsg.phase,
					Body:  mboxMsg.body,
				}
				sendMsg(&msg)
			}

			go func() {
				for mboxMsg := range msgChan {
					msg := &messageMsg{
						Side:  mboxMsg.side,
						Phase: mboxMsg.phase,
						Body:  mboxMsg.body,
					}
					sendMsg(msg)
				}
			}()

			openMailbox = mbox
		case *releaseMsg:
			ackMsg(m.ID)

			nameplate, err := strconv.Atoi(m.Nameplate)
			if err != nil {
				errMsg(m.ID, m, errors.New("No nameplate found"))
				continue
			}

			ts.mu.Lock()
			delete(ts.nameplates, int16(nameplate))
			ts.mu.Unlock()

			sendMsg(&releasedRespMsg{})
		case *addMsg:
			ackMsg(m.ID)

			openMailbox.Add(sideID, m)

		case *closeMsg:
			ackMsg(m.ID)

			sendMsg(&closedRespMsg{})

		default:
			log.Printf("Test server got unexpected message: %v", msg)
		}
	}
}
