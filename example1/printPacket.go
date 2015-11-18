package main

import (
	"fmt"
	"io"
	"log"

	"github.com/sunwxg/goshark"
)

func main() {

	file := "../2.pcap"
	d := goshark.NewDecoder()
	if err := d.DecodeStart(file); err != nil {
		log.Println("Decode start fail:", err)
		return
	}
	defer d.DecodeEnd()

	for {
		f, err := d.NextPacket()
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println("Get packet fail:", err)
			return
		}

		fmt.Printf("%s", f)
	}
}
