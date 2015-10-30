//goshark decode IP packets
package goshark

import (
	"strings"
	"testing"

	"github.com/jteeuwen/go-pkg-xmlx"
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

func setup() (d *xmlx.Document) {
	d = xmlx.New()
	if err := d.LoadString(data, nil); err != nil {
		return
	}
	return
}

func TestNextPacket(t *testing.T) {

	file := "2.pcap"
	d := CreateDecoder()
	if err := d.DecodeStart(file); err != nil {
		t.Fatalf("Decode start fail")
	}
	defer d.DecodeEnd()

	f, err := d.NextPacket()
	if err != nil {
		t.Fatalf("get packet fail")
	}

	expected := 11
	if len(f) != expected {
		t.Fatalf("expected (%d). get (%d)", expected, len(f))
	}
}

func TestIskey(t *testing.T) {
	d := setup()
	node := d.SelectNode("", "packet")
	field := createField(node)

	expected := "50"

	key := "f50"
	get, ok := field.Iskey(key)
	if !ok {
		t.Fatalf("Can't find key: %s", key)
	}

	if strings.Compare(get, expected) != 0 {
		t.Fatalf("expect: (%s) but get: (%s)", expected, get)
	}
}
