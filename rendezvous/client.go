// Package rendezvous provides a client for magic wormhole rendezvous servers.
package rendezvous

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous/internal/msgs"
	"github.com/psanford/wormhole-william/version"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// NewClient returns a Rendezvous client. URL is the websocket
// url of Rendezvous server. SideID is the id for the client to
// use to distinguish messages in a mailbox from the other client.
// AppID is the application identity string of the client.
//
// Two clients can only communicate if they have the same AppID.
func NewClient(url, sideID, appID string, opts ...ClientOption) *Client {
	c := &Client{
		url:         url,
		sideID:      sideID,
		appID:       appID,
		pendingMsgs: make([]pendingMsg, 0, 2),

		mailboxMsgs:           make([]MailboxEvent, 0),
		pendingMailboxWaiters: make(map[uint32]chan int),

		pendingMsgWaiters: make(map[uint32]chan uint32),
	}

	for _, opt := range opts {
		opt.setValue(c)
	}

	return c
}

type pendingMsg struct {
	// id will be monotonically increasing for each received
	// message so waiters can know if they have seen all the
	// pending messages or not
	id      uint32
	msgType string
	raw     []byte
}

type Client struct {
	url       string
	appID     string
	sideID    string
	mailboxID string

	nameplate string

	agentString  string
	agentVersion string

	wsClient *websocket.Conn

	mailboxMsgs           []MailboxEvent
	pendingMailboxWaiters map[uint32]chan int

	pendingMsgIDCntr     uint32
	pendingMsgWaiterCntr uint32

	sendCmdMu sync.Mutex

	pendingMsgMu      sync.Mutex
	pendingMsgs       []pendingMsg
	pendingMsgWaiters map[uint32]chan uint32

	clientState clientState
	err         error
}

type MailboxEvent struct {
	// Error will be non nil if an error occurred
	// while waiting for messages
	Error error
	Side  string
	Phase string
	Body  string
}

type clientState int32

const (
	statePending clientState = iota
	stateOpen
	stateError
	stateClosed
)

func (c clientState) String() string {
	switch c {
	case statePending:
		return "Pending"
	case stateOpen:
		return "Open"
	case stateError:
		return "Error"
	case stateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown client state: %d", c)
	}
}

func (c *Client) closeWithError(err error) {
	atomic.StoreInt32((*int32)(&c.clientState), int32(stateError))
	c.err = err
}

type ConnectInfo struct {
	MOTD              string
	CurrentCLIVersion string
}

// Connect opens a connection and binds to the rendezvous server. It
// returns the Welcome information the server responds with.
func (c *Client) Connect(ctx context.Context) (*ConnectInfo, error) {
	swapped := atomic.CompareAndSwapInt32((*int32)(&c.clientState), int32(statePending), int32(stateOpen))
	if !swapped {
		return nil, fmt.Errorf("current client state %s != pending, cannot connect", c.clientState)
	}

	var err error
	c.wsClient, _, err = websocket.Dial(ctx, c.url, nil)
	if err != nil {
		wrappedErr := fmt.Errorf("dial %s: %s", c.url, err)
		c.closeWithError(wrappedErr)
		return nil, wrappedErr
	}

	go c.readMessages(ctx)

	var welcome msgs.Welcome
	err = c.readMsg(ctx, &welcome)
	if err != nil {
		c.closeWithError(err)
		return nil, err
	}

	if welcome.Welcome.Error != "" {
		err := fmt.Errorf("server error: %s", err)
		c.closeWithError(err)
		return nil, err
	}

	if err := c.bind(ctx, c.sideID, c.appID); err != nil {
		c.closeWithError(err)
		return nil, err
	}

	info := ConnectInfo{
		MOTD:              welcome.Welcome.MOTD,
		CurrentCLIVersion: welcome.Welcome.CurrentCLIVersion,
	}

	return &info, nil
}

func (c *Client) searchPendingMsgs(ctx context.Context, msgType string) *pendingMsg {
	c.pendingMsgMu.Lock()
	defer c.pendingMsgMu.Unlock()

	for i, pending := range c.pendingMsgs {
		if pending.msgType == msgType {
			copyMsg := pending
			orig := c.pendingMsgs
			c.pendingMsgs = c.pendingMsgs[:i]
			c.pendingMsgs = append(c.pendingMsgs, orig[i+1:]...)

			return &copyMsg
		}
	}

	return nil
}

func (c *Client) registerWaiter() (uint32, <-chan uint32) {
	nextID := atomic.AddUint32(&c.pendingMsgWaiterCntr, 1)
	ch := make(chan uint32, 1)

	c.pendingMsgMu.Lock()
	defer c.pendingMsgMu.Unlock()
	c.pendingMsgWaiters[nextID] = ch
	if len(c.pendingMsgs) > 0 {
		ch <- c.pendingMsgs[len(c.pendingMsgs)-1].id
	}

	return nextID, ch
}

func (c *Client) deregisterWaiter(id uint32) {
	c.pendingMsgMu.Lock()
	defer c.pendingMsgMu.Unlock()
	delete(c.pendingMsgWaiters, id)
}

func (c *Client) readMsg(ctx context.Context, m interface{}) error {
	expectMsgType := msgType(m)

	waiterID, ch := c.registerWaiter()
	defer c.deregisterWaiter(waiterID)

	for {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}

		msg := c.searchPendingMsgs(ctx, expectMsgType)
		if msg != nil {

			err := json.Unmarshal(msg.raw, m)
			if err != nil {
				wrappedErr := fmt.Errorf("JSON unmarshal: %s", err)
				return wrappedErr
			}

			return nil
		}
	}
}

func msgType(msg interface{}) string {
	ptr := reflect.TypeOf(msg)

	if ptr.Kind() != reflect.Ptr {
		panic("msg must be a pointer")
	}

	structType := ptr.Elem()

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if field.Tag.Get("json") == "type" {
			return field.Tag.Get("rendezvous_value")
		}
	}
	return ""
}

// CreateMailbox allocates a nameplate, claims it, and then opens
// the associated mailbox. It returns the nameplate id string.
func (c *Client) CreateMailbox(ctx context.Context) (string, error) {
	nameplateResp, err := c.allocateNameplate(ctx)
	if err != nil {
		c.closeWithError(err)
		return "", err
	}

	claimed, err := c.claimNameplate(ctx, nameplateResp.Nameplate)
	if err != nil {
		c.closeWithError(err)
		return "", err
	}
	c.nameplate = nameplateResp.Nameplate

	err = c.openMailbox(ctx, claimed.Mailbox)
	if err != nil {
		c.closeWithError(err)
		return "", err
	}

	return nameplateResp.Nameplate, nil
}

// AttachMailbox opens an existing mailbox and releases the associated
// nameplate.
func (c *Client) AttachMailbox(ctx context.Context, nameplate string) error {
	claimed, err := c.claimNameplate(ctx, nameplate)
	if err != nil {
		c.closeWithError(err)
		return err
	}
	c.nameplate = nameplate

	err = c.openMailbox(ctx, claimed.Mailbox)
	if err != nil {
		c.closeWithError(err)
		return err
	}

	return nil
}

// ListNameplates returns a list of active nameplates on the
// rendezvous server.
func (c *Client) ListNameplates(ctx context.Context) ([]string, error) {
	var (
		nameplatesResp msgs.Nameplates
		listReq        msgs.List
	)

	_, err := c.sendAndWait(ctx, &listReq)
	if err != nil {
		return nil, err
	}

	err = c.readMsg(ctx, &nameplatesResp)
	if err != nil {
		return nil, err
	}

	outNameplates := make([]string, len(nameplatesResp.Nameplates))
	for i, np := range nameplatesResp.Nameplates {
		outNameplates[i] = np.ID
	}

	return outNameplates, nil
}

// AddMessage adds a message to the opened mailbox. This must be called after
// either CreateMailbox or AttachMailbox.
func (c *Client) AddMessage(ctx context.Context, phase, body string) error {
	addReq := msgs.Add{
		Phase: phase,
		Body:  body,
	}

	_, err := c.sendAndWait(ctx, &addReq)
	return err
}

// MsgChan returns a channel of Mailbox message events.
// Each message from the other side will be published to this channel.
func (c *Client) MsgChan(ctx context.Context) <-chan MailboxEvent {
	resultChan := make(chan MailboxEvent)
	go c.recvMailboxMsgs(ctx, resultChan)
	return resultChan
}

func (c *Client) recvMailboxMsgs(ctx context.Context, outCh chan MailboxEvent) {
	id, notified := c.registerMailboxWaiter()
	defer c.deregisterMailboxWaiter(id)

	nextOffset := 0
	var nextMsg *MailboxEvent

OUTER:
	for {

		// loop over all pending messages we haven't sent
		// to outCh yet
		for {
			c.pendingMsgMu.Lock()
			if len(c.mailboxMsgs)-1 >= nextOffset {
				nextMsg = &c.mailboxMsgs[nextOffset]
			}
			c.pendingMsgMu.Unlock()

			if nextMsg == nil {
				break
			}

			nextOffset++

			if nextMsg.Side != c.sideID {
				// Only send messages from the other side
				outCh <- *nextMsg

				if c.nameplate != "" {
					// release the nameplate when we get a response from the other side
					c.releaseNameplate(ctx, c.nameplate)
					c.nameplate = ""
				}

			}
			nextMsg = nil
		}

		// wait for any new mailbox messages
		_, ok := <-notified
		if !ok {
			break OUTER
		}
	}

	close(outCh)
}

func (c *Client) registerMailboxWaiter() (uint32, <-chan int) {
	nextID := atomic.AddUint32(&c.pendingMsgWaiterCntr, 1)
	ch := make(chan int, 1)

	c.pendingMsgMu.Lock()
	defer c.pendingMsgMu.Unlock()
	c.pendingMailboxWaiters[nextID] = ch

	return nextID, ch
}

func (c *Client) deregisterMailboxWaiter(id uint32) {
	c.pendingMsgMu.Lock()
	defer c.pendingMsgMu.Unlock()
	delete(c.pendingMailboxWaiters, id)
}

type Mood string

const (
	Happy  Mood = "happy"
	Lonely Mood = "lonely"
	Scary  Mood = "scary"
	Errory Mood = "errory"
)

// Close sends mood to server and then tears down the connection.
func (c *Client) Close(ctx context.Context, mood Mood) error {
	if mood == "" {
		mood = Happy
	}

	if c.wsClient == nil {
		return errors.New("Close called on non-open rendezvous connection")
	}

	defer func() {
		if c.wsClient != nil {
			c.wsClient.Close(websocket.StatusNormalClosure, "")
			c.wsClient = nil
		}
	}()

	var closedResp msgs.ClosedResp

	closeReq := msgs.Close{
		Mood:    string(mood),
		Mailbox: c.mailboxID,
	}

	_, err := c.sendAndWait(ctx, &closeReq)
	if err != nil {
		return err
	}

	err = c.readMsg(ctx, &closedResp)
	return err
}

// sendAndWait sends a message to the rendezvous server and waits
// for an ack response.
func (c *Client) sendAndWait(ctx context.Context, msg interface{}) (*msgs.Ack, error) {
	id, err := c.prepareMsg(msg)
	if err != nil {
		return nil, err
	}

	c.sendCmdMu.Lock()
	err = wsjson.Write(ctx, c.wsClient, msg)
	if err != nil {
		c.sendCmdMu.Unlock()
		return nil, err
	}

	var ack msgs.Ack
	err = c.readMsg(ctx, &ack)
	if err != nil {
		c.sendCmdMu.Unlock()
		return nil, err
	}
	c.sendCmdMu.Unlock()

	if ack.ID != id {
		return nil, fmt.Errorf("got ack for different message. got %s send: %+v", ack.ID, msg)
	}

	return &ack, nil
}

// prepareMsg populates the ID and Type fields for a message.
// It returns the ID string or an error.
func (c *Client) prepareMsg(msg interface{}) (string, error) {
	id := crypto.RandHex(2)

	ptr := reflect.TypeOf(msg)

	if ptr.Kind() != reflect.Ptr {
		return "", errors.New("msg must be a pointer")
	}

	st := ptr.Elem()
	val := reflect.ValueOf(msg).Elem()

	var (
		foundType bool
		foundID   bool
	)

	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		if field.Name == "Type" {
			msgType, _ := field.Tag.Lookup("rendezvous_value")
			if msgType == "" {
				return "", errors.New("type filed missing rendezvous_value struct tag")
			}
			ff := val.Field(i)
			ff.SetString(msgType)
			foundType = true
		} else if field.Name == "ID" {
			ff := val.Field(i)
			ff.SetString(id)
			foundID = true
		}
	}

	if !foundID || !foundType {
		return id, errors.New("msg type missing required field(s): Type and/or ID")
	}

	return id, nil
}

func (c *Client) agentID() (string, string) {
	agent := c.agentString
	if agent == "" {
		agent = version.AgentString
	}
	v := c.agentVersion
	if v == "" {
		v = version.AgentVersion
	}

	return agent, v
}

func (c *Client) bind(ctx context.Context, side, appID string) error {
	agent, version := c.agentID()

	bind := msgs.Bind{
		Side:          side,
		AppID:         appID,
		ClientVersion: []string{agent, version},
	}

	_, err := c.sendAndWait(ctx, &bind)
	return err
}

func (c *Client) allocateNameplate(ctx context.Context) (*msgs.AllocatedResp, error) {
	var (
		allocReq    msgs.Allocate
		allocedResp msgs.AllocatedResp
	)

	_, err := c.sendAndWait(ctx, &allocReq)
	if err != nil {
		return nil, err
	}

	err = c.readMsg(ctx, &allocedResp)
	if err != nil {
		return nil, err
	}

	return &allocedResp, nil
}

func (c *Client) claimNameplate(ctx context.Context, nameplate string) (*msgs.ClaimedResp, error) {
	var claimResp msgs.ClaimedResp

	claimReq := msgs.Claim{
		Nameplate: nameplate,
	}

	_, err := c.sendAndWait(ctx, &claimReq)
	if err != nil {
		return nil, err
	}

	err = c.readMsg(ctx, &claimResp)
	if err != nil {
		return nil, err
	}

	return &claimResp, nil
}

func (c *Client) releaseNameplate(ctx context.Context, nameplate string) error {
	var releasedResp msgs.ReleasedResp

	releaseReq := msgs.Release{
		Nameplate: nameplate,
	}

	_, err := c.sendAndWait(ctx, &releaseReq)
	if err != nil {
		return err
	}

	err = c.readMsg(ctx, &releasedResp)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) openMailbox(ctx context.Context, mailbox string) error {
	c.pendingMsgMu.Lock()
	c.mailboxID = mailbox
	c.pendingMsgMu.Unlock()

	open := msgs.Open{
		Mailbox: mailbox,
	}

	_, err := c.sendAndWait(ctx, &open)
	return err
}

// readMessages reads off the websocket and dispatches messages
// to either pendingMsg or pendingMailboxMsg.
func (c *Client) readMessages(ctx context.Context) {
	for {
		if err := ctx.Err(); err != nil {
			c.closeWithError(err)
			break
		}

		_, msg, err := c.wsClient.Read(ctx)
		if err != nil {
			wrappedErr := fmt.Errorf("WS Read: %s", err)
			c.closeWithError(wrappedErr)
			break
		}

		var genericMsg msgs.GenericServerMsg
		err = json.Unmarshal(msg, &genericMsg)
		if err != nil {
			wrappedErr := fmt.Errorf("JSON unmarshal: %s", err)
			c.closeWithError(wrappedErr)
			break
		}

		if genericMsg.Type == "message" {
			var mm msgs.Message
			err := json.Unmarshal(msg, &mm)
			if err != nil {
				wrappedErr := fmt.Errorf("JSON unmarshal: %s", err)
				c.closeWithError(wrappedErr)
				break
			}

			mboxMsg := MailboxEvent{
				Side:  mm.Side,
				Phase: mm.Phase,
				Body:  mm.Body,
			}

			c.pendingMsgMu.Lock()
			c.mailboxMsgs = append(c.mailboxMsgs, mboxMsg)
			maxOffset := len(c.mailboxMsgs) - 1

			for _, waiter := range c.pendingMailboxWaiters {
				select {
				case waiter <- maxOffset:
				default:
				}
			}
			c.pendingMsgMu.Unlock()
		} else {
			nextID := atomic.AddUint32(&c.pendingMsgIDCntr, 1)

			c.pendingMsgMu.Lock()
			c.pendingMsgs = append(c.pendingMsgs, pendingMsg{
				id:      nextID,
				msgType: genericMsg.Type,
				raw:     msg,
			})

			for _, waiter := range c.pendingMsgWaiters {
				select {
				case waiter <- nextID:
				default:
				}
			}
			c.pendingMsgMu.Unlock()
		}

	}
}
