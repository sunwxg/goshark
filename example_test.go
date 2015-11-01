package goshark_test

import (
	"fmt"
	"goshark"
	"log"
)

func ExampleDecoder_DecodeStart() {
	d := goshark.NewDecoder()
	if err := d.DecodeStart("input_file"); err != nil {
		log.Fatalf("Decode start fail: %s", err)
	}
	defer d.DecodeEnd()
}

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
