//goshark decode IP packets
package goshark

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

var data string = `<packet>
<proto name="f1">
    <field name="f20" show="20"/>
    <field name="f21" show="21">
      <field name="f30" show="30">
        <field name="f40" show="40"/>
        <field name="f42" show="42"/>
        <field name="f41" show="41">
          <field name="f50" show="50"/>
        </field>
      </field>
    </field>
</proto>
</packet>
`

func TestNextPacket(t *testing.T) {

	file := "2.pcap"
	d := NewDecoder()
	if err := d.DecodeStart(file); err != nil {
		t.Fatalf("Decode start fail: %s", err)
	}
	defer d.DecodeEnd()

	f, err := d.NextPacket()
	if err != nil {
		t.Fatalf("get packet fail")
	}

	expected := 1
	get := len(f.Childs[0].Childs[1].Attrs)
	if get != expected {
		t.Fatalf("expected (%d). get (%d)", expected, get)
	}
}

func TestIskey(t *testing.T) {
	d := NewDecoder()
	r := bytes.NewReader([]byte(data))

	f, err := d.LoadPacket(r)
	if err != nil {
		t.Fatalf("load packet fail")
	}

	expected := "50"

	key := "f50"
	get, ok := f.Iskey(key)
	if !ok {
		t.Fatalf("Can't find key: %s", key)
	}

	if strings.Compare(get, expected) != 0 {
		t.Fatalf("expect: (%s) but get: (%s)", expected, get)
	}
}

func TestGetField(t *testing.T) {
	d := NewDecoder()
	r := bytes.NewReader([]byte(data))

	f, err := d.LoadPacket(r)
	if err != nil {
		t.Fatalf("load packet fail")
	}

	key := "f41"
	get, ok := f.Getfield(key)
	if !ok {
		t.Fatalf("Can't find key: %s", key)
	}

	buf := make([]byte, 100, 200)
	w := bytes.NewBuffer(buf)

	fmt.Fprintln(w, get)
	len := w.Len()
	expected := 121
	if len != expected {
		t.Fatalf("expect: (%d) but get: (%d)", expected, len)
	}
}
