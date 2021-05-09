package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

var pktEnd = []byte("\r\n")
var start = []byte("start")

const (
	pktNoSize   = 2
	pktSzSize   = 2
	pktHdrSize  = pktNoSize + pktSzSize
	pktEndSize  = 2 // len(pktEnd)
	pktInfSize  = pktHdrSize + pktEndSize
	pktMaxSize  = 0b1111_1111_1111_1111
	pktMaxCount = 0b1111_1111_1111_1111
)

var (
	isServer     bool
	pktSize      int
	pktCount     int
	addr         string
	rwTimeout    time.Duration
	sendInterval time.Duration
	useMem       bool
	help         bool
)

func init() {
	flag.BoolVar(&isServer, "l", false, "listen")
	flag.BoolVar(&useMem, "m", false, "store received data in memory")
	flag.IntVar(&pktSize, "p", 1500, "paket size")
	flag.IntVar(&pktCount, "cnt", 60000, "send / receive count")
	flag.DurationVar(&rwTimeout, "t", 5*time.Second, "read and write operation timeout")
	flag.DurationVar(&sendInterval, "i", 2*time.Millisecond, "send interval")
	flag.BoolVar(&help, "h", false, "print help")
}

func usage() {
	fmt.Print("Simple command line utility for test udp package losses.\n")
	fmt.Printf("Usage: %s [flags] <listen or dest address>.\n\n", os.Args[0])
	fmt.Print("WARN: -p and -cnd should match on both sending and receiving sides.\n\n")

	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	if help {
		usage()
		return
	}
	flag.CommandLine.Usage = usage
	if flag.NArg() == 0 && flag.NFlag() == 0 {
		usage()
		return
	}
	addr = flag.Arg(0)
	if pktCount > pktMaxCount {
		fmt.Fprintf(os.Stderr, "max packet count: %d", pktMaxCount)
	}
	if pktSize > pktMaxSize {
		fmt.Fprintf(os.Stderr, "max packet size: %d", pktMaxSize)
	}
	if addr == "" {
		fmt.Fprintln(os.Stderr, "address not specified (use -h for info)")
		os.Exit(1)
	}
	if isServer {
		serve()
		return
	}
	upload()
}

func serve() {
	con, err := net.ListenPacket("udp", addr)
	ep(err)
	defer con.Close()
	var (
		no  uint16
		pkt paket
		s   store
		i   int
	)
	defer func() {
		fmt.Printf("total packets received: %d\n", i)
		if i != pktCount {
			fmt.Printf("packet loss: %d (%.2f%%)\n",
				pktCount-i, float64(pktCount-i)/float64(pktCount)*100)
		}
	}()
	fmt.Println("waiting for incoming connection")
	buf := make([]byte, len(start))
	con.SetReadDeadline(time.Time{})
	_, _, err = con.ReadFrom(buf)
	ep(err)
	if !bytes.Equal(buf, start) {
		panic(fmt.Sprintf("unexpected first bytes: %s\n", string(buf)))
	}
	fmt.Println("received start command")
	for i = 0; i < pktCount; i++ {
		err := pkt.readFrom(con)
		if err != nil {
			return
		}
		if no >= pkt.no {
			fmt.Printf("wrong packet order: prev no: %d, cur no: %d\n", no, pkt.no)
		}
		no = pkt.no
		s.save(&pkt)
	}
	fmt.Println(s.checkSum())
}

func upload() {
	con, err := net.Dial("udp", addr)
	ep(err)
	defer con.Close()
	h := md5.New()
	var pkt paket
	bb := make([]byte, pktSize-pktInfSize)
	_, err = con.Write(start)
	ep(err)
	var i int
	defer func() {
		fmt.Printf("total packets sent: %d\n", i)
	}()
	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()
	for i = 0; i < pktCount; i++ {
		<-ticker.C
		_, err := rand.Read(bb)
		ep(err)
		_, err = h.Write(bb)
		ep(err)
		pkt.apply(bb)
		pkt.writeTo(con)
	}

	fmt.Printf("%x\n", h.Sum(nil))
}

type store []byte

func (s *store) save(p *paket) {
	if !useMem {
		return
	}
	if *s == nil {
		(*s) = make([]byte, (pktSize-pktInfSize)*pktCount)
	}

	copy((*s)[int(p.no-1)*(pktSize-pktInfSize):], p.data)
}

func (s store) checkSum() string {
	h := md5.New()
	_, _ = h.Write(s)
	return fmt.Sprintf("%x", h.Sum(nil))
}

type paket struct {
	no   uint16
	size uint16
	data []byte
	buf  []byte
	from net.Addr
}

func (p *paket) reset() {
	if p.buf == nil {
		p.buf = make([]byte, pktSize)
	}
	p.no = 0
	p.size = 0
	p.from = nil
}

func (p *paket) readFrom(con net.PacketConn) error {
	p.reset()
	con.SetReadDeadline(time.Now().Add(rwTimeout))
	n, addr, err := con.ReadFrom(p.buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	ep(err)

	if p.from != nil && p.from.String() != addr.String() {
		panic("remote address changed")
	}

	buf := p.buf[:n]
	if len(buf) < pktInfSize {
		panic("to few bytes received")
	}

	no := binary.LittleEndian.Uint16(buf[0:pktNoSize])
	plSize := binary.LittleEndian.Uint16(buf[pktNoSize:pktHdrSize])
	if len(buf)-pktInfSize != int(plSize) {
		panic("expected and received packet size are not match")
	}
	if !bytes.Equal(buf[len(buf)-pktEndSize:], pktEnd) {
		panic("unexpected packet end")
	}

	p.data = buf[pktHdrSize : pktHdrSize+plSize]
	p.no = no
	p.size = plSize
	p.from = addr

	return nil
}

func (p *paket) apply(b []byte) {
	if p.no == 0 {
		p.reset()
	}
	if len(b) > pktSize-pktInfSize {
		panic("payload to long")
	}
	p.size = uint16(len(b))
	p.no++
	binary.LittleEndian.PutUint16(p.buf, p.no)
	binary.LittleEndian.PutUint16(p.buf[pktNoSize:], p.size)
	copy(p.buf[pktHdrSize:], b)
	copy(p.buf[pktHdrSize+len(b):], pktEnd)
}

func (p *paket) writeTo(w io.Writer) {
	_, err := w.Write(p.buf)
	if err != nil {
		panic(err)
	}
}

func info() {
	ifs, err := net.Interfaces()
	ep(err)
	for i := range ifs {
		fmt.Printf("%+v\n", ifs[i])
		addrs, err := ifs[i].Addrs()
		ep(err)
		for ii := range addrs {
			fmt.Printf("    %+v\n", addrs[ii])
		}
	}
}

func ep(err error) {
	if err == nil || errors.Is(err, io.EOF) {
		return
	}
	panic(err)
}
