package queue

import (
	"encoding/binary"
	"testing"
)

func TestPacketParsing(t *testing.T) {
	b := make([]byte, 40)
	b[0] = 0x45
	b[9] = 6
	b[12] = 127
	b[15] = 1
	b[16] = 127
	b[19] = 1
	binary.BigEndian.PutUint16(b[20:22], 9000)
	binary.BigEndian.PutUint16(b[22:24], 80)
	b[33] = 2
	f, _, err := Parse(b, "incoming")
	if err != nil || f.Local.Port() != 80 || f.Remote.Port() != 9000 {
		t.Fatal(f, err)
	}
	f, _, err = Parse(b, "outgoing")
	if err != nil || f.Local.Port() != 9000 {
		t.Fatal(f, err)
	}
	b[6] = 0x20
	if _, _, err = Parse(b, "incoming"); err == nil {
		t.Fatal("fragment accepted")
	}
	for i := 0; i < 40; i++ {
		Parse(b[:i], "incoming")
	}
}
