package rendezvous

import (
	"context"
	"testing"
)

type msgMissingType struct {
	Side  string `json:"side"`
	AppID string `json:"appid"`
	ID    string `json:"id"`
}

func TestPrepareMessage(t *testing.T) {
	c := NewClient("ws://example.com:2345")

	claimReq := ClaimMsg{
		Nameplate: "8",
	}

	id, _, err := c.prepareMsg(claimReq)
	if err == nil || err.Error() != "msg must be a pointer" {
		t.Errorf("Expected prepareMsg to error on non-pointer parameter but got: %s", err)
	}

	if id != "" {
		t.Errorf("Expected id not to be set for error case but it was")
	}

	id, _, err = c.prepareMsg(&claimReq)
	if err != nil {
		t.Errorf("Got error preparing message when non was expected: %s", err)
	}

	if claimReq.Type != "claim" {
		t.Errorf("Expected Type to be 'claim' but was %s", claimReq.Type)
	}

	if claimReq.ID == "" {
		t.Error("Expected ID to be set but was not")
	}

	if claimReq.ID != id {
		t.Errorf("Expected ID to match return val but it did not %s != %s", claimReq.ID, id)
	}

	c.waitMu.Lock()
	waiter := c.ackWaiters[claimReq.ID]
	c.waitMu.Unlock()

	if waiter == nil {
		t.Fatalf("Expected an ackWaiter but didn't find one")
	}

	_, _, err = c.prepareMsg(&msgMissingType{})
	if err == nil || err.Error() != "msg type missing required field(s): Type and/or ID" {
		t.Errorf("Expected msgMissingtype to error on missing fields but got: %s", err)
	}
}

func TestWaitForMsg(t *testing.T) {
	c := NewClient("ws://example.com:2345")

	var resp AllocatedRespMsg

	ctx := context.Background()

	_, err := c.waitFor(ctx, resp)
	if err == nil || err.Error() != "resultMsg must be a pointer" {
		t.Errorf("Unexpected error from waitFor: %s", err)
	}

	_, err = c.waitFor(ctx, &resp)
	if err != nil {
		t.Errorf("Unexpected error from waitFor: %s", err)
	}
}
