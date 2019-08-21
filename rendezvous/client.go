// Package rendezvous provides a websocket rendezvous client.
package rendezvous

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

func NewClient(url string) *Client {
	return &Client{
		url:            url,
		recvChan:       make(chan interface{}),
		sendChan:       make(chan interface{}),
		errorChan:      make(chan error, 1),
		ackWaiters:     make(map[string]chan interface{}),
		msgTypeWaiters: make(map[string]*msgWaiter),
	}
}

type msgWaiter struct {
	msg        interface{}
	resultChan chan struct{}
	msgType    string
	id         uint32
}

type waitFor struct {
	msgType string
	ID      string
}

type Client struct {
	url   string
	appID string

	wsClient *websocket.Conn

	closed int32

	recvChan  chan interface{}
	sendChan  chan interface{}
	errorChan chan error

	waitMu          sync.Mutex
	ackWaiters      map[string]chan interface{}
	waiterIDCounter uint32
	msgTypeWaiters  map[string]*msgWaiter
}

func (c *Client) closeWithError(err error) {
	c.errorChan <- err
	close(c.recvChan)
}

func (c *Client) Run(ctx context.Context) {
	var err error
	c.wsClient, _, err = websocket.DefaultDialer.Dial(c.url, nil)
	if err != nil {
		c.closeWithError(fmt.Errorf("Dial %s: %s", c.url, err))
		return
	}
	defer c.wsClient.Close()

	for {
		var genericMsg genericServerMsg

		_, msg, err := c.wsClient.ReadMessage()
		if err != nil {
			c.closeWithError(fmt.Errorf("WS Read: %s", err))
			break
		}

		err = json.Unmarshal(msg, &genericMsg)
		if err != nil {
			c.closeWithError(fmt.Errorf("JSON unmarshal: %s", err))
			break
		}

		log.Printf("recv: %+v", genericMsg)

		protoType, found := msgMap[genericMsg.Type]
		if !found {
			log.Printf("Unknown msg type: %s %v %s\n", genericMsg.Type, genericMsg, msg)
			continue
		}

		var (
			resultPtr   interface{}
			foundWaiter bool
			mw          *msgWaiter
		)

		c.waitMu.Lock()
		if w := c.msgTypeWaiters[genericMsg.Type]; w != nil {
			mw = w
			foundWaiter = true
			delete(c.msgTypeWaiters, genericMsg.Type)
		}
		c.waitMu.Unlock()

		if mw != nil {
			resultPtr = mw.msg

		} else {
			t := reflect.TypeOf(protoType)
			val := reflect.New(t)
			resultPtr = val.Interface()
		}

		err = json.Unmarshal(msg, resultPtr)
		if err != nil {
			c.closeWithError(fmt.Errorf("JSON unmarshal: %s", err))
			break
		}

		if genericMsg.ID != "" {
			c.waitMu.Lock()
			waiter := c.ackWaiters[genericMsg.ID]
			if waiter != nil {
				waiter <- resultPtr
				foundWaiter = true
			}
			delete(c.ackWaiters, genericMsg.ID)
			c.waitMu.Unlock()
		}

		if mw != nil {
			mw.resultChan <- struct{}{}
		}

		if foundWaiter {
			// skip generic recv chan if a specific caller is waiting for a message
			continue
		}

		c.recvChan <- resultPtr
	}
}

func (c *Client) Send(msg interface{}) error {
	if atomic.LoadInt32(&c.closed) > 0 {
		return errors.New("Client closed")
	}

	_, _, err := c.prepareMsg(msg)
	if err != nil {
		return err
	}

	fmt.Printf("send msg: %+v \n", msg)

	return c.wsClient.WriteJSON(msg)
}

func (c *Client) SendAndWait(ctx context.Context, msg interface{}) (*AckMsg, error) {
	if atomic.LoadInt32(&c.closed) > 0 {
		return nil, errors.New("Client closed")
	}

	id, waitChan, err := c.prepareMsg(msg)
	if err != nil {
		return nil, err
	}

	fmt.Printf("send msg: %+v\n", msg)
	err = c.wsClient.WriteJSON(msg)
	if err != nil {
		return nil, err
	}

	select {
	case result := <-waitChan:
		ack, ok := result.(*AckMsg)
		if !ok {
			return nil, fmt.Errorf("resp not an ack: %v\n", result)
		}
		return ack, nil
	case <-ctx.Done():
		c.waitMu.Lock()
		delete(c.ackWaiters, id)
		c.waitMu.Unlock()
		return nil, ctx.Err()
	}
}

func (c *Client) nextWaiterID() uint32 {
	return atomic.AddUint32(&c.waiterIDCounter, 1)
}

func (c *Client) waitFor(ctx context.Context, resultMsg interface{}) (*msgWaiter, error) {
	var msgType string

	ptr := reflect.TypeOf(resultMsg)

	if ptr.Kind() != reflect.Ptr {
		return nil, errors.New("resultMsg must be a pointer")
	}

	st := ptr.Elem()

	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		if field.Name == "Type" {
			msgType, _ = field.Tag.Lookup("rendezvous_value")
		}
	}

	if msgType == "" {
		return nil, fmt.Errorf("No Type field or rendezvous_value struct tag on Type field for %T", resultMsg)
	}

	resultChan := make(chan struct{}, 1)

	waiter := msgWaiter{
		msg:        resultMsg,
		msgType:    msgType,
		resultChan: resultChan,
		id:         c.nextWaiterID(),
	}

	c.waitMu.Lock()
	defer c.waitMu.Unlock()
	_, existing := c.msgTypeWaiters[msgType]
	if existing {
		return nil, fmt.Errorf("Existing waiter already registered for %s", msgType)
	}

	c.msgTypeWaiters[msgType] = &waiter

	return &waiter, nil
}

func (c *Client) clearWaiter(waiter *msgWaiter) {
	c.waitMu.Lock()
	defer c.waitMu.Unlock()

	gotWaiter := c.msgTypeWaiters[waiter.msgType]
	if gotWaiter == nil {
		return
	}

	if gotWaiter.id == waiter.id {
		delete(c.msgTypeWaiters, waiter.msgType)
	}
}

func (c *Client) prepareMsg(msg interface{}) (id string, waitChan chan interface{}, resultErr error) {
	var foundFreeID bool
	waitChan = make(chan interface{}, 1)

	defer func() {
		// don't leak pending acks if we encounter an error
		if resultErr != nil && id != "" && foundFreeID {
			c.waitMu.Lock()
			delete(c.ackWaiters, id)
			c.waitMu.Unlock()
			id = ""
		}
	}()

	c.waitMu.Lock()
	for i := 0; i < 100; i++ {
		id = randHex(2)
		if _, occupied := c.ackWaiters[id]; !occupied {
			c.ackWaiters[id] = waitChan
			foundFreeID = true
			break
		}
		id = ""
	}
	c.waitMu.Unlock()

	if !foundFreeID {
		return id, nil, errors.New("Failed to find free message id")
	}

	ptr := reflect.TypeOf(msg)

	if ptr.Kind() != reflect.Ptr {
		return id, nil, errors.New("msg must be a pointer")
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
				return id, nil, errors.New("Type filed missing rendezvous_value struct tag")
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
		return id, nil, errors.New("msg type missing required field(s): Type and/or ID")
	}

	return id, waitChan, nil
}

func (c *Client) Bind(ctx context.Context, side, appID string) (*AckMsg, error) {
	bind := BindMsg{
		Side:  side,
		AppID: appID,
	}

	return c.SendAndWait(ctx, &bind)
}

func (c *Client) AllocateNameplate(ctx context.Context) (*AllocatedRespMsg, error) {
	var (
		allocReq    AllocateMsg
		allocedResp AllocatedRespMsg
	)

	msgWaiter, err := c.waitFor(ctx, &allocedResp)
	if err != nil {
		return nil, err
	}

	_, err = c.SendAndWait(ctx, &allocReq)
	if err != nil {
		return nil, err
	}

	select {
	case <-msgWaiter.resultChan:
		return &allocedResp, nil
	case <-ctx.Done():
		c.clearWaiter(msgWaiter)
		return nil, ctx.Err()
	}
}

func (c *Client) ClaimNameplate(ctx context.Context, nameplate string) (*ClaimedRespMsg, error) {
	var claimResp ClaimedRespMsg

	claimReq := ClaimMsg{
		Nameplate: nameplate,
	}

	msgWaiter, err := c.waitFor(ctx, &claimResp)
	if err != nil {
		return nil, err
	}

	_, err = c.SendAndWait(ctx, &claimReq)
	if err != nil {
		return nil, err
	}

	select {
	case <-msgWaiter.resultChan:
		return &claimResp, nil
	case <-ctx.Done():
		c.clearWaiter(msgWaiter)
		return nil, ctx.Err()
	}
}

func (c *Client) OpenMailbox(ctx context.Context, mailbox string) error {
	openMsg := OpenMsg{
		Mailbox: mailbox,
	}

	_, err := c.SendAndWait(ctx, &openMsg)
	return err
}

func (c *Client) Add(ctx context.Context, phase, body string) error {
	addReq := AddMsg{
		Phase: phase,
		Body:  body,
	}

	_, err := c.SendAndWait(ctx, &addReq)
	return err
}

func (c *Client) RecvChan() <-chan interface{} {
	return c.recvChan
}

func (c *Client) ErrorChan() <-chan error {
	return c.errorChan
}

type prepareable interface {
	prepare() (interface{}, string)
}
