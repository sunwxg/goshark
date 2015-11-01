package goshark_test

import (
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
