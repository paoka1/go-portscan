package syn

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

type synScan struct {
	// macAddr
	srcMac, gwMac net.HardwareAddr
	// eth dev(pcap)
	devName string

	// gateway (if applicable), and source IP addresses to use
	gw, srcIp net.IP

	// pcap
	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in send method
	opts gopacket.SerializeOptions

	// buffer 复用
	bufPool *sync.Pool

	macCache *MacCacheMap
}

// ScanSyn get synScan struct
func ScanSyn(ip string) (ss *synScan) {
	srcIp, srcMac, gw, devName, err := GetRouterV4(net.IP(ip))
	if err != nil {
		log.Fatalln(err)
	}

	if devName == "" {
		err = errors.New("get router info fail: no dev name")
		log.Fatalln(err)
	}

	ss = &synScan{
		srcMac:  srcMac,
		devName: devName,
		gw:      gw,
		srcIp:   srcIp,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		bufPool: &sync.Pool{
			New: func() interface{} {
				return gopacket.NewSerializeBuffer()
			},
		},
		macCache: &MacCacheMap{
			MacCache: make(map[string]net.HardwareAddr),
		},
	}

	handle, err := pcap.OpenLive(devName, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatalln(err)
	}

	// Set filter, reduce the number of monitoring packets
	_ = handle.SetBPFFilter(fmt.Sprintf("ether dst %s && (arp || tcp)", srcMac.String()))
	ss.handle = handle

	return ss
}

// GetGatewayMac Get Gateway mac
func (ss *synScan) GetGatewayMac() {
	var err error

	if ss.gw != nil {
		// get gateway mac addr
		var dstMac net.HardwareAddr
		dstMac, err = ss.getHwAddrV4(ss.gw)
		if err != nil {
			log.Println(err)
		}
		ss.gwMac = dstMac
	}
}

// ListenPackage listen packets on the network
func (ss *synScan) ListenPackage() {
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       nil,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    ss.srcIp,
		DstIP:    []byte{},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 0,
		DstPort: 0,
		RST:     true,
		ACK:     true,
		Seq:     1,
	}

	// Decode
	var ipLayer layers.IPv4
	var tcpLayer layers.TCP
	var arpLayer layers.ARP
	var ethLayer layers.Ethernet
	var foundLayerTypes []gopacket.LayerType

	// Parse the packet
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&tcpLayer,
		&arpLayer,
	)

	var err error
	var data []byte
	var ipStr string
	var _port uint16

	for {
		// Read in the next packet
		data, _, err = ss.handle.ReadPacketData()
		if err != nil {
			continue
		}

		// Decode TCP or ARP Packet
		err = parser.DecodeLayers(data, &foundLayerTypes)
		if len(foundLayerTypes) == 0 {
			continue
		}

		// Arp
		if arpLayer.SourceProtAddress != nil {
			ipStr = net.IP(arpLayer.SourceProtAddress).String()
			ss.macCache.AddMacIp(ipStr, arpLayer.SourceHwAddress)
			// Clean arp parse status
			arpLayer.SourceProtAddress = nil
			continue
		}

		// Tcp Match ip and port
		if tcpLayer.DstPort != 0 && tcpLayer.DstPort >= 49000 && tcpLayer.DstPort <= 59000 {
			ipStr = ipLayer.SrcIP.String()
			_port = uint16(tcpLayer.SrcPort)
			// IP
			if !IsIpExist(ipStr) {
				continue
			} else {
				// PORT
				if Ipc.HasPort(ipStr, _port) {
					continue
				} else {
					// record
					Ipc.RecordPort(ipStr, _port)
				}
			}

			if tcpLayer.SYN && tcpLayer.ACK {
				// Reply to target
				eth.DstMAC = ethLayer.SrcMAC
				ip4.DstIP = ipLayer.SrcIP
				tcp.DstPort = tcpLayer.SrcPort
				tcp.SrcPort = tcpLayer.DstPort
				// RST && ACK
				tcp.Ack = tcpLayer.Seq + 1
				tcp.Seq = tcpLayer.Ack
				_ = tcp.SetNetworkLayerForChecksum(&ip4)
				_ = ss.send(&eth, &ip4, &tcp)
				SaveResult(ipLayer.SrcIP.String(), _port, "open")
			} else {
				if tcpLayer.RST {
					SaveResult(ipLayer.SrcIP.String(), _port, "closed")
				}
			}
			// Clean tcp parse status
			tcpLayer.DstPort = 0
		}
	}
}

// SendPackage send packages
func (ss *synScan) SendPackage(ip net.IP, port uint16) (err error) {
	ip = ip.To4()
	if ip == nil {
		return errors.New("ip is not ipv4")
	}

	ipStr := ip.String()

	// First off, get the MAC address we should be sending packets to
	var dstMac net.HardwareAddr
	if ss.gwMac != nil {
		dstMac = ss.gwMac
	} else {
		// 内网 IP
		mac := ss.macCache.GetMacByIp(ipStr)
		if mac != nil {
			dstMac = mac
		} else {
			dstMac, err = ss.getHwAddrV4(ip)
			if err != nil {
				return
			}
		}
	}

	// Construct all the network layers we need
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    ss.srcIp,
		DstIP:    ip,
		Version:  4,
		TTL:      128,
		Id:       uint16(40000 + rand.Intn(10000)),
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		// Random source port and used to determine receive dst port range
		SrcPort: layers.TCPPort(49000 + rand.Intn(10000)),
		DstPort: layers.TCPPort(port),
		SYN:     true,
		Window:  65280,
		Seq:     uint32(500000 + rand.Intn(10000)),
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				// 1360
				OptionData: []byte{0x05, 0x50},
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x08},
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
		},
	}
	_ = tcp.SetNetworkLayerForChecksum(&ip4)

	// Send one packet per loop iteration until we've sent packets
	_ = ss.send(&eth, &ip4, &tcp)

	return nil
}

// getHwAddrV4 get the destination hardware address for our packets
func (ss *synScan) getHwAddrV4(arpDst net.IP) (mac net.HardwareAddr, err error) {
	ipStr := arpDst.String()

	// Prepare the layers to send for an ARP request
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(ss.srcMac),
		SourceProtAddress: []byte(ss.srcIp),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	if err = ss.sendArp(&eth, &arp); err != nil {
		return nil, err
	}

	start := time.Now()
	var retry int

	for {
		mac = ss.macCache.GetMacByIp(ipStr)
		if mac != nil {
			return mac, nil
		}
		// Wait for an ARP reply
		if time.Since(start) > time.Millisecond*800 {
			return nil, errors.New("timeout getting ARP reply")
		}
		retry += 1
		if retry%25 == 0 {
			if err = ss.send(&eth, &arp); err != nil {
				return nil, err
			}
		}

		time.Sleep(time.Millisecond * 10)
	}
}

// send sends the given layers as a single packet on the network
func (ss *synScan) send(l ...gopacket.SerializableLayer) error {
	buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		_ = buf.Clear()
		ss.bufPool.Put(buf)
	}()
	if err := gopacket.SerializeLayers(buf, ss.opts, l...); err != nil {
		return err
	}
	return ss.handle.WritePacketData(buf.Bytes())
}

// sendArp send the given layers as a single packet on the network, need fix padding
func (ss *synScan) sendArp(l ...gopacket.SerializableLayer) error {
	buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		_ = buf.Clear()
		ss.bufPool.Put(buf)
	}()
	if err := gopacket.SerializeLayers(buf, ss.opts, l...); err != nil {
		return err
	}
	// Need fix padding
	return ss.handle.WritePacketData(buf.Bytes()[:42])
}
