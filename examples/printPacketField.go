package main

import (
	"fmt"
	"log"

	"github.com/sunwxg/goshark"
)

func main() {

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

	s, ok := f.Getfield("igmp")
	if ok {
		fmt.Printf("%s", s)
	}
}
