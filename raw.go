package main

import (
	"fmt"
	"net"
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

func proto(n int, done chan bool) {
	// fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	// f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	// for {
	// 	buf := make([]byte, 1024)
	// 	numRead, err := f.Read(buf)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// 	fmt.Printf("% X\n", buf[:numRead])
	// 	done <- true
	// }

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
	done := make(chan bool)
	go proto(4, done)
	<-done
}
