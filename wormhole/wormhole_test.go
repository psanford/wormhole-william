package wormhole

import (
	"context"
	"testing"

	"github.com/psanford/wormhole-william/rendezvous/rendezvousservertest"
)

func TestWormholeSendRecvText(t *testing.T) {
	ctx := context.Background()

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	url := rs.WebSocketURL()

	c0 := NewClient()
	c0.RendezvousURL = url

	c1 := NewClient()
	c1.RendezvousURL = url

	secretText := "Hialeah-deviltry"
	code, statusChan, err := c0.SendText(ctx, secretText)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := c1.RecvText(ctx, code)
	if err != nil {
		t.Fatalf("Recv err: %s", err)
	}

	status := <-statusChan
	if !status.OK {
		t.Fatalf("Send side error: %+v", status)
	}

	if msg != secretText {
		t.Fatalf("Got %s expected %s", msg, secretText)
	}
}
