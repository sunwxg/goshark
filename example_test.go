package goshark_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/sunwxg/goshark"
)

func Example() {

	file := "2.pcap"
	d := goshark.NewDecoder()
	if err := d.DecodeStart(file); err != nil {
		log.Println("Decode start fail:", err)
		return
	}
	defer d.DecodeEnd()

	f, err := d.NextPacket()
	if err != nil {
		log.Println("Get packet fail:", err)
		return
	}

	key := "igmp.maddr"
	value, ok := f.Iskey(key)
	if ok {
		fmt.Printf("key: %s\nvalue: %s\n", key, value)
	}

	//Output:
	//key: igmp.maddr
	//value: 224.0.0.251
}

func ExampleDecoder_DecodeStart() {
	d := goshark.NewDecoder()
	if err := d.DecodeStart("input_file"); err != nil {
		log.Fatalf("Decode start fail: %s", err)
	}
	defer d.DecodeEnd()
}

func ExampleDecoder_LoadPacket() {
	data := `
<packet>
  <proto name="igmp">
    <field name="igmp.type" show="22"/>
    <field name="igmp.maddr" show="224.0.0.251"/>
  </proto>
</packet>
`
	d := goshark.NewDecoder()
	r := bytes.NewReader([]byte(data))

	f, err := d.LoadPacket(r)
	if err != nil {
		log.Fatalf("load packet fail")
	}
	fmt.Printf("%s", f)

	//Output:
	//. []
	//. . [igmp]
	//. . . [igmp.type] 22
	//. . . [igmp.maddr] 224.0.0.251
}
