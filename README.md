## goshark
Package goshark use tshark to decode IP packet and create data struct to analysis packet.

###Examples
```go
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
```
Output:
```
key: igmp.maddr
value: 224.0.0.251
```
