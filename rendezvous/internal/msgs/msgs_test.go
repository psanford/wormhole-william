package msgs

import (
	"testing"
)

var msgMap = map[string]RendezvousValue{
	"welcome":    &Welcome{},
	"bind":       &Bind{},
	"allocate":   &Allocate{},
	"ack":        &Ack{},
	"allocated":  &AllocatedResp{},
	"claim":      &Claim{},
	"claimed":    &ClaimedResp{},
	"open":       &Open{},
	"add":        &Add{},
	"message":    &Message{},
	"list":       &List{},
	"nameplates": &Nameplates{},
	"release":    &Release{},
	"released":   &ReleasedResp{},
	"error":      &Error{},
	"close":      &Close{},
	"closed":     &ClosedResp{},
}

func TestStructTags(t *testing.T) {
	for n, iface := range msgMap {
		value := iface.RendezvousValue()
		if value != n {
			t.Errorf("msgMap key / Type struct tag rendezvous_value mismatch: key=%s tag=%s struct=%T", n, value, iface)
		}
	}
}
