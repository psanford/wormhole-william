package wormhole

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/psanford/wormhole-william/rendezvous/rendezvousservertest"
)

func TestWormholeSendRecvText(t *testing.T) {
	ctx := context.Background()

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	url := rs.WebSocketURL()

	// disable transit relay
	DefaultTransitRelayAddress = ""

	var c0 Client
	c0.RendezvousURL = url

	var c1 Client
	c1.RendezvousURL = url

	secretText := "Hialeah-deviltry"
	code, statusChan, err := c0.SendText(ctx, secretText)
	if err != nil {
		t.Fatal(err)
	}

	nameplate := strings.SplitN(code, "-", 2)[0]

	// recv with wrong code
	msg, err := c1.Receive(ctx, fmt.Sprintf("%s-intermarrying-aliased", nameplate))
	if err != errDecryptFailed {
		t.Fatalf("Recv side expected decrypt failed due to wrong code but got: %s", err)
	}

	status := <-statusChan
	if status.OK || status.Error != errDecryptFailed {
		t.Fatalf("Send side expected decrypt failed but got status: %+v", status)
	}

	code, statusChan, err = c0.SendText(ctx, secretText)
	if err != nil {
		t.Fatal(err)
	}

	// recv with correct code
	msg, err = c1.Receive(ctx, code)
	if err != nil {
		t.Fatalf("Recv side got unexpected err: %s", err)
	}

	msgBody, err := ioutil.ReadAll(msg)
	if err != nil {
		t.Fatalf("Recv side got read err: %s", err)
	}

	if string(msgBody) != secretText {
		t.Fatalf("Got Message does not match sent secret got=%s sent=%s", msgBody, secretText)
	}

	status = <-statusChan
	if !status.OK || status.Error != nil {
		t.Fatalf("Send side expected OK status but got: %+v", status)
	}
}
