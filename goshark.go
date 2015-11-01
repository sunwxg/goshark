//Package goshark use tshark to decode IP packet and get data struct to analysis packet.
package goshark

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
)

//Data struct of IP packet
type Field struct {
	Field  map[string]string
	Childs []*Field
	Parent *Field
}

type Decoder struct {
	Cmd         *exec.Cmd
	W           sync.WaitGroup
	Reader      io.ReadCloser
	BufioReader *bufio.Reader
}

//Implements Decoder
func NewDecoder() (decoder *Decoder) {
	decoder = &Decoder{}
	return decoder
}

//Start decoding. When finished, should use DecodeEnd
//to close decoding. Use defer DecodeEnd after DecodeStart
//success.
//Return err ???
func (d *Decoder) DecodeStart(file string) (err error) {

	cmd := exec.Command("tshark", "-T", "pdml", "-r", file)

	d.Cmd = cmd
	d.Reader, err = cmd.StdoutPipe()
	if err != nil {
		return
	}

	d.BufioReader = bufio.NewReader(d.Reader)

	err = cmd.Start()
	if err != nil {
		return
	}

	return
}

//Close decoding
func (d *Decoder) DecodeEnd() error {
	if err := d.Cmd.Wait(); err != nil {
		log.Println("cmd wait fail:", err)
		return err
	}

	return nil
}

//Get the one packet from Decoder. When at then end of file,
//get error io.EOF with nil field.
func (d *Decoder) NextPacket() (field *Field, err error) {
	var out []byte
	var startRecord bool = false

	for {
		line, _, err := d.BufioReader.ReadLine()
		if err == io.EOF {
			return field, err
		} else if err != nil {
			return field, err
		}

		if strings.Compare(string(line), "<packet>") == 0 {
			startRecord = true
		}

		if startRecord {
			out = append(out, line...)
			out = append(out, byte('\n'))

			if strings.Compare(string(line), "</packet>") == 0 {
				break
			}
		}
	}

	r := bytes.NewReader(out)
	field, err = d.LoadPacket(r)
	if err != nil {
		return field, err
	}

	return
}

func newField() *Field {
	f := Field{}
	f.Field = make(map[string]string, 5)
	return &f
}

func (f *Field) addChild(c *Field) {
	f.Childs = append(f.Childs, c)
}

//Change xml data to Field struct. Xml data is gotten from tshark output.
//When xml data isn't right, return xml decoding error
func (d *Decoder) LoadPacket(r io.Reader) (field *Field, err error) {
	xd := xml.NewDecoder(r)
	field = newField()
	field.Parent = nil

	currentField := field
	var t *Field

	for {
		tok, err := xd.Token()
		if err != nil {
			if err == io.EOF {
				return field, nil
			}
			return field, err
		}

		switch tt := tok.(type) {
		case xml.SyntaxError:
			return field, errors.New(tt.Error())
		case xml.StartElement:
			key, value := getKeyValue(tt.Attr)
			t = newField()
			t.Field[key] = value

			t.Parent = currentField
			currentField.addChild(t)

			currentField = t

		case xml.EndElement:
			currentField = currentField.Parent
			if currentField == nil {
				return field, nil
			}
		}
	}
}

//Get attribute "name" and "show" as map key and value
func getKeyValue(attr []xml.Attr) (key, keyvalue string) {
	for _, v := range attr {
		name := v.Name.Local
		value := v.Value

		switch {
		case len(value) == 0:
			continue
		case strings.Compare(name, "name") == 0:
			key = value
		case strings.Compare(name, "show") == 0:
			keyvalue = value
		}
	}
	return key, keyvalue
}

func printMap(field Field, buf *[]string, i int) {
	var s string

	for key, value := range field.Field {
		s = fmt.Sprintf("%s", strings.Repeat(". ", i))
		*buf = append(*buf, s)

		s = fmt.Sprintf("[%s] %s\n", key, value)
		*buf = append(*buf, s)
	}

	for _, f := range field.Childs {
		printMap(*f, buf, i+1)
	}
}

func (field Field) String() string {
	buf := make([]string, 10, 20)
	printMap(field, &buf, 0)

	return strings.Join(buf, "")
}

func (field Field) iterateIskey(key string, f *Field, r *bool) {

	if _, ok := field.Field[key]; ok {
		*r = true
		*f = field
		return
	}

	for _, d := range field.Childs {
		d.iterateIskey(key, f, r)
	}
}

//Get the value by key in a Field. When key doesn't exist,
//return ok=false and value=nil
func (field Field) Iskey(key string) (value string, ok bool) {
	f := newField()
	ok = false

	field.iterateIskey(key, f, &ok)
	value, ok = f.getvalue(key)

	return value, ok
}

//Get the Field by key i a Field. When key doesn't exist,
//return ok=false and f=nil
func (field Field) Getfield(key string) (f Field, ok bool) {
	ok = false

	field.iterateIskey(key, &f, &ok)

	return f, ok
}

func (field Field) getvalue(key string) (value string, ok bool) {

	if value, ok := field.Field[key]; ok {
		ok = true
		return value, ok
	}

	ok = false
	return
}
