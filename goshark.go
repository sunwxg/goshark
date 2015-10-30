//goshark
//
package goshark

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/jteeuwen/go-pkg-xmlx"
)

type Field map[string]interface{}

type Decoder struct {
	Packet      *xmlx.Document
	Cmd         *exec.Cmd
	W           sync.WaitGroup
	Reader      io.ReadCloser
	BufioReader *bufio.Reader
}

func CreateDecoder() (decoder *Decoder) {

	decoder = &Decoder{}
	decoder.Packet = xmlx.New()

	return decoder
}

func (d *Decoder) DecodeStart(file string) (err error) {

	cmd := exec.Command("tshark", "-T", "pdml", "-r", file)

	d.Cmd = cmd
	d.Reader, err = cmd.StdoutPipe()
	if err != nil {
		//log.Println("create pipe err:", err)
		return
	}

	d.BufioReader = bufio.NewReader(d.Reader)

	err = cmd.Start()
	if err != nil {
		//log.Println("cmd start error", err)
		return
	}

	return
}

func (d *Decoder) DecodeEnd() error {
	if err := d.Cmd.Wait(); err != nil {
		log.Println("cmd wait fail:", err)
		return err
	}

	//log.Println("cmd exit success")
	return nil
}

func (d *Decoder) NextPacket() (field Field, err error) {
	var out []byte

	for {
		line, _, err := d.BufioReader.ReadLine()
		if err == io.EOF {
			break
		} else if err != nil {
			//log.Priptln("read line fail:", err)
			return field, err
		}

		out = append(out, line...)
		out = append(out, byte('\n'))
		if strings.Compare(string(line), "</packet>") == 0 {
			break
		}

	}

	if err := d.Packet.LoadString(string(out), nil); err != nil {
		return field, err
	}

	node := d.Packet.SelectNode("", "packet")
	field = createField(node)

	return
}

func createField(node *xmlx.Node) (field Field) {
	field = make(Field, 20)
	iterateField(node, field)

	return field
}

func iterateField(node *xmlx.Node, field Field) {

	if len(node.Attributes) != 0 {
		var key string
		var v interface{}

		for _, a := range node.Attributes {
			name := a.Name.Local
			value := a.Value

			switch {
			case len(value) == 0:
				continue
			case strings.Compare(name, "name") == 0:
				key = value
			case strings.Compare(name, "show") == 0:
				v = value
			}
		}

		field[key] = v
	}

	if len(node.Children) == 0 {
		return
	}

	for i, c := range node.Children {
		cfield := make(Field, 100)
		field["c"+strconv.Itoa(i)] = cfield
		iterateField(c, cfield)
	}
}

func printMap(field Field, buf *[]string, i int) {

	maps := make([]interface{}, 20)
	var s string

	for key, value := range field {
		if _, ok := value.(Field); ok {
			maps = append(maps, value)
			continue
		}

		s = fmt.Sprintf("%s", strings.Repeat(". ", i))
		*buf = append(*buf, s)

		if value == nil {
			value = ""
		}
		s = fmt.Sprintf("[%s] %s\n", key, value)
		*buf = append(*buf, s)
	}

	for _, value := range maps {
		if v, ok := value.(Field); ok {
			printMap(v, buf, i+1)
		}
	}
}

func (field Field) String() string {
	buf := make([]string, 5)
	printMap(field, &buf, 0)

	return strings.Join(buf, "")
}

func (field Field) iterateIskey(key string, f *Field, r *bool) {

	if _, ok := field[key]; ok {
		*r = true
		*f = field
		return
	}

	for _, d := range field {
		if v, ok := d.(Field); ok {
			v.iterateIskey(key, f, r)
			if *r {
				return
			}
		}
	}
}

func (field Field) Iskey(key string) (value string, ok bool) {
	f := make(Field)
	ok = false

	field.iterateIskey(key, &f, &ok)
	value, ok = f.getvalue(key)

	return value, ok
}

func (field Field) Getfield(key string) (f Field, ok bool) {
	ok = false

	field.iterateIskey(key, &f, &ok)

	return f, ok
}

func (field Field) getvalue(key string) (value string, ok bool) {

	if value, ok := field[key].(string); ok {
		ok = true
		return value, ok
	}

	ok = false
	return

}
