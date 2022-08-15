package msgs

import (
	"testing"
)

var msgMap = map[string]RendezvousType{
	"welcome":    NewWelcome(),
	"bind":       NewBind("", "", nil),
	"allocate":   NewAllocate(),
	"ack":        NewAck(),
	"allocated":  NewAllocatedResp(),
	"claim":      NewClaim(""),
	"claimed":    NewClaimedResp(),
	"open":       NewOpen(""),
	"add":        NewAdd("", ""),
	"message":    NewMessage(),
	"list":       NewList(),
	"nameplates": NewNameplates(),
	"release":    NewRelease(""),
	"released":   NewReleasedResp(),
	"error":      NewError("", nil),
	"close":      NewClose("", ""),
	"closed":     NewClaimedResp(),
}

func TestStructTags(t *testing.T) {
	for n, iface := range msgMap {
		value := iface.GetType()
		if value != n {
			t.Errorf("msgMap key / Type struct tag rendezvous_value mismatch: key=%s tag=%s struct=%T", n, value, iface)
		}
	}
}
