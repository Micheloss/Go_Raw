package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device          string = "en1"
	snapshot_len    int32  = 1024
	promiscuous     bool   = true
	err             error
	timeout         time.Duration = 1
	handle          *pcap.Handle
	total_packs     = 0
	total_tcp       = 0
	total_tcp_SYN   = 0
	total_tcp_ACK   = 0
	total_tcp_data  = 0
	total_icmp      = 0
	total_udp       = 0
	ip_dst_detected = ""
)

type Report struct {
	XMLName    xml.Name `xml:"Net Report"`
	ID         int      `xml:"id"`
	TCPackets  int      `xml:"tcpPackets"`
	UDPackets  int      `xml:udpPackets"`
	ICMPackets int      `xml:"icmpPackets"`
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	// ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	// if ethernetLayer != nil {
	// 	fmt.Println("Ethernet layer detected.")
	// 	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	// 	fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
	// 	fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
	// 	// Ethernet type is typically IPv4 but could be ARP or other
	// 	fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
	// 	fmt.Println()
	// }

	// // Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	// if ipLayer != nil {
	// 	fmt.Println("IPv4 layer detected.")
	ip, _ := ipLayer.(*layers.IPv4)

	// 	// IP layer variables:
	// 	// Version (Either 4 or 6)
	// 	// IHL (IP Header Length in 32-bit words)
	// 	// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
	// 	// Checksum, SrcIP, DstIP
	// 	fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
	// 	fmt.Println("Protocol: ", ip.Protocol)
	// 	fmt.Println()
	// }

	if !strings.Contains(ip_dst_detected, string(ip.DstIP)) {
		names, err4 := net.LookupAddr(string(ip.DstIP))
		if err4 != nil {
			names[0] = "error-resolving"
		}
		ip_dst_detected = ip_dst_detected + "|" + string(ip.DstIP) + " " + names[0]

	}
	total_packs++
	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		total_tcp++
		// fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN {
			total_tcp_SYN++
		} else {

			if tcp.ACK {
				total_tcp_ACK++
			} else {

				total_tcp_data++

			}
		}
		// // TCP layer variables:
		// // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		// fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		// fmt.Println("Sequence number: ", tcp.Seq)
		// fmt.Println()
	} else {

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			//	fmt.Println("UDP layer detected.")
			// 	udp, _ := udpLayer.(*layers.UDP)

			// 	// TCP layer variables:
			// 	// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
			// 	// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
			// 	fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
			// 	fmt.Println("Content number: ", udp.Contents)
			// 	fmt.Println()
			total_udp++
		} else {

			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer != nil {
				total_icmp++
				//fmt.Println("ICMP layer detected.")
				// icmp, _ := icmpLayer.(*layers.ICMPv4)

				// // TCP layer variables:
				// // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
				// // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
				// fmt.Printf("ICMP type: ", icmp.TypeCode.Code())

				fmt.Println()
			}

		}
	}
	// Iterate over all layers, printing out each layer type
	// fmt.Println("All packet layers:")
	// for _, layer := range packet.Layers() {
	// 	fmt.Println("- ", layer.LayerType())
	// }

	// // When iterating through packet.Layers() above,
	// // if it lists Payload layer then that is the same as
	// // this applicationLayer. applicationLayer contains the payload
	// applicationLayer := packet.ApplicationLayer()
	// if applicationLayer != nil {
	// 	fmt.Println("Application layer/Payload found.")
	// 	fmt.Printf("%s\n", applicationLayer.Payload())

	// 	// Search for a string inside the payload
	// 	if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
	// 		fmt.Println("HTTP found!")
	// 	}
	// }

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

func main() {
	//done_icmp := make(chan bool)

	v := &Report{ID: 100, TCPackets: total_tcp, UDPackets: total_udp, ICMPackets: total_icmp}

	filename := "Net-Report"
	file, _ := os.Create(filename)

	xmlWriter := io.Writer(file)

	enc := xml.NewEncoder(xmlWriter)
	enc.Indent("  ", " ")
	if err5 := enc.Encode(v); err5 != nil {
		fmt.Println(err5)
	}

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		go printPacketInfo(packet)

		if total_packs > 600 {
			break
		}
	}

	p_tcp := float32(total_tcp) / float32(total_packs) * 100
	p_udp := float32(total_udp) / float32(total_packs) * 100
	p_icmp := float32(total_icmp) / float32(total_packs) * 100
	fmt.Println("Total packets captured: ", total_packs)
	fmt.Println("Total TCP packets captured: ", total_tcp, ". ", p_tcp, " %"+" of total")
	fmt.Println("Total UDP packets captured:  ", total_udp, ". ", p_udp, " %"+"of total")
	fmt.Println("Total ICMP packets captured:  ", total_icmp, ". ", p_icmp, " %"+"of total")
	fmt.Println(" -----------------------------------  ")
	fmt.Println("           IPs contacted      ")
	fmt.Println(" -----------------------------------  ")
	fmt.Println(ip_dst_detected)

	//<-done_icmp
	//<-done_tcp
}
