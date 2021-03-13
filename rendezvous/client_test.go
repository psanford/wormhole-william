package rendezvous

import (
	"context"
	"reflect"
	"testing"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous/rendezvousservertest"
	"github.com/psanford/wormhole-william/version"
)

func TestBasicClient(t *testing.T) {
	ts := rendezvousservertest.NewServer()
	defer ts.Close()

	side0 := crypto.RandSideID()
	side1 := crypto.RandSideID()
	appID := "superlatively-abbeys"

	c0 := NewClient(ts.WebSocketURL(), side0, appID)

	ctx := context.Background()

	info, err := c0.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if info.MOTD != rendezvousservertest.TestMotd {
		t.Fatalf("MOTD got=%s expected=%s", info.MOTD, rendezvousservertest.TestMotd)
	}

	gotAgents := ts.Agents()
	expectAgents := [][]string{
		{version.AgentString, version.AgentVersion},
	}

	if !reflect.DeepEqual(gotAgents, expectAgents) {
		t.Fatalf("got agents=%v expected=%v", gotAgents, expectAgents)
	}

	nameplate, err := c0.CreateMailbox(ctx)
	if err != nil {
		t.Fatal(err)
	}

	c1 := NewClient(ts.WebSocketURL(), side1, appID)
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

func TestCustomUserAgent(t *testing.T) {
	ts := rendezvousservertest.NewServer()
	defer ts.Close()

	side0 := crypto.RandSideID()
	appID := "nightclubs-reasonableness"

	agentString := "deafening-buttermilk"
	agentVersion := "v1.2.3"
	c0 := NewClient(ts.WebSocketURL(), side0, appID, WithVersion(agentString, agentVersion))

	ctx := context.Background()

	_, err := c0.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	gotAgents := ts.Agents()
	expectAgents := [][]string{
		{agentString, agentVersion},
	}

	if !reflect.DeepEqual(gotAgents, expectAgents) {
		t.Fatalf("got agents=%v expected=%v", gotAgents, expectAgents)
	}

	c0.Close(ctx, "")
}
