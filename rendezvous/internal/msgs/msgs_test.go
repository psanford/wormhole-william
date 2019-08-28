package msgs

import (
	"reflect"
	"testing"
)

func TestStructTags(t *testing.T) {
	for n, iface := range MsgMap {
		st := reflect.TypeOf(iface)
		for i := 0; i < st.NumField(); i++ {
			field := st.Field(i)
			if field.Name == "Type" {
				tagVal, _ := field.Tag.Lookup("rendezvous_value")
				if tagVal != n {
					t.Errorf("msgMap key / Type struct tag rendezvous_value mismatch: key=%s tag=%s struct=%T", n, tagVal, iface)
				}
			}
		}
	}
}
