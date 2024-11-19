package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	scionpila "github.com/netsys-lab/scion-pila"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/scionproto/scion/pkg/snet"
)

func main() {

	go func() {
		listen()
	}()

	time.Sleep(3 * time.Second)
	dial()
}

type QPartsQuicTracer struct {
	Tracer       logging.ConnectionTracer
	Context      context.Context
	Perspective  logging.Perspective
	ConnectionID quic.ConnectionID
}

func dial() {
	remote := "1-150,127.0.0.1:4443"
	raddr, err := snet.ParseUDPAddr(remote)
	if err != nil {
		panic(err)
	}
	rAddrPort := raddr.Host.AddrPort()
	rudpAddr := net.UDPAddrFromAddrPort(rAddrPort)

	local := "1-150,127.0.0.1:11443"
	laddr, err := snet.ParseUDPAddr(local)
	if err != nil {
		panic(err)
	}

	lAddrPort := laddr.Host.AddrPort()
	ludpAddr := net.UDPAddrFromAddrPort(lAddrPort)

	conn, err := net.ListenUDP("udp4", ludpAddr)
	if err != nil {
		panic(err)
	}

	remoteVerifyFunc := scionpila.VerifyQUICCertificateChainsHandler("/etc/scion/certs", remote)
	tracers := map[quic.ConnectionID]QPartsQuicTracer{}
	conf := quic.Config{
		Tracer: func(context context.Context, perspective logging.Perspective, connectionID quic.ConnectionID) *logging.ConnectionTracer {
			fmt.Println("Obtain Tracer")
			t := QPartsQuicTracer{}

			tracer := &logging.ConnectionTracer{}
			tracer.AcknowledgedPacket = func(encLevel logging.EncryptionLevel, packetNumber logging.PacketNumber) {
				fmt.Println("Acked Packet")
			}
			tracer.LostPacket = func(encLevel logging.EncryptionLevel, packetNumber logging.PacketNumber, reason logging.PacketLossReason) {
				fmt.Println("Lost Packet")
				fmt.Println(reason)
			}
			t.Tracer = *tracer
			t.Context = context
			t.Perspective = perspective
			t.ConnectionID = connectionID
			tracers[connectionID] = t
			return tracer
		},
	}

	session, err := quic.Dial(context.Background(), conn, rudpAddr, &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: remoteVerifyFunc, NextProtos: []string{"qparts"}}, &conf)
	if err != nil {
		panic(err)
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}

	for {
		data := make([]byte, 1000)
		_, err = stream.Write(data)
		if err != nil {
			panic(err)
		}
		time.Sleep(1 * time.Second)
	}
}

func listen() {
	local := "1-150,127.0.0.1:4443"
	addr, err := snet.ParseUDPAddr(local)
	if err != nil {
		panic(err)
	}

	lAddr := addr.Host.AddrPort()
	udpAddr := net.UDPAddrFromAddrPort(lAddr)
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}

	client := scionpila.NewSCIONPilaClient("http://localhost:8843")

	key := scionpila.NewPrivateKey()
	csr, err := scionpila.NewCertificateSigningRequest(key)
	if err != nil {
		log.Fatal(err)
	}

	certificate, err := client.FetchCertificateFromSigningRequest(local, csr)
	if err != nil {
		log.Fatal(err)
	}

	tlsCerts, err := scionpila.CreateTLSCertificate(certificate, key)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := quic.Listen(conn, &tls.Config{InsecureSkipVerify: true, Certificates: tlsCerts, NextProtos: []string{"qparts"}}, &quic.Config{})
	if err != nil {
		panic(err)
	}

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			panic(err)
		}

		go func() {
			for {
				stream, err := sess.AcceptStream(context.Background())
				if err != nil {
					panic(err)
				}

				data := make([]byte, 1000)

				go func() {
					for {

						n, err := stream.Read(data)
						if err != nil {
							panic(err)
						}
						fmt.Println("Read Header", n)
						fmt.Printf("Received %x\n", sha256.Sum256(data[:n]))
						fmt.Println("---------------------------------")
						// fmt.Println(string())
					}

				}()
			}
		}()
	}
}
