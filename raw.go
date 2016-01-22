package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// type Header_IP4 struct {
// 	Version  int         // protocol version
// 	Len      int         // header length
// 	TOS      int         // type-of-service
// 	TotalLen int         // packet total length
// 	ID       int         // identification
// 	Flags    HeaderFlags // flags
// 	FragOff  int         // fragment offset
// 	TTL      int         // time-to-live
// 	Protocol int         // next protocol
// 	Checksum int         // checksum
// 	Src      net.IP      // source address
// 	Dst      net.IP      // destination address
// 	Options  []byte      // options, extension headers
// }

var (
	device       string = "lo0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 0
	handle       *pcap.Handle
)

func tcp(n int, done chan bool) {

	//protocol := "tcp"

	//var packetConn PacketConn

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet)
	}

	// fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	// f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	// for {
	// 	buf := make([]byte, 1024)
	// 	numRead, err := f.Read(buf)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// 	fmt.Printf("% X\n", buf[:numRead])
	// }

	done <- true

}

func icmp(n int, done chan bool) {

	protocol := "icmp"
	netaddr, _ := net.ResolveIPAddr("ip4", "127.0.0.1")
	conn, _ := net.ListenIP("ip4:"+protocol, netaddr)

	buf := make([]byte, 1024)
	for i := 0; i < n; i++ {

		numRead, _, _ := conn.ReadFrom(buf)
		fmt.Printf("% X\n", buf[:numRead])

	}

	done <- true

}

func main() {
	//done_icmp := make(chan bool)
	done_tcp := make(chan bool)
	//go icmp(4, done_icmp)
	go tcp(4, done_tcp)
	//<-done_icmp
	<-done_tcp
}
