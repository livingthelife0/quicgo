package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{derBytes},
			PrivateKey:  key,
		}},
		NextProtos: []string{"quicgo"}, // Match the client's protocol
	}
}

func runServer(addr string, windowSize int, bufferSize int) {
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(windowSize),
		InitialConnectionReceiveWindow: uint64(windowSize),
		MaxIdleTimeout:                 60 * time.Second,
		Versions:                       []quic.Version{quic.Version1, quic.Version2},
	}

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), quicConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Server listening on %s", addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		log.Printf("Accepted connection from %s", conn.RemoteAddr())

		go handleConnection(conn, bufferSize)
	}
}

func handleConnection(conn quic.Connection, bufferSize int) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Stream accept error: %v", err)
			return
		}
		log.Printf("Accepted new stream from %s", conn.RemoteAddr())

		go func(stream quic.Stream) {
			buf := make([]byte, bufferSize)
			for {
				_, err := stream.Write(buf)
				if err != nil {
					log.Printf("Stream write error: %v", err)
					return
				}
			}
		}(stream)
	}
}

func runClient(addr string, duration time.Duration, windowSize int, bufferSize int) {
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(windowSize),
		InitialConnectionReceiveWindow: uint64(windowSize),
		MaxIdleTimeout:                 60 * time.Second,
		Versions:                       []quic.Version{quic.Version1, quic.Version2},
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicgo"}, // Match the server's protocol
	}

	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, quicConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Client connected to %s", addr)

	numStreams := 32
	streams := make([]quic.Stream, numStreams)
	for i := range streams {
		var err error
		streams[i], err = conn.OpenStreamSync(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Client opened a stream to %s", addr)
	}

	for _, stream := range streams {
		_, err := stream.Write([]byte("1"))
		if err != nil {
			log.Fatalf("Error writing byte: %v", err)
		}
	}

	start := time.Now()
	var totalBytes int64
	buf := make([]byte, bufferSize)

	wg := &sync.WaitGroup{}
	wg.Add(numStreams)
	for _, stream := range streams {
		go func(stream quic.Stream) {
			defer wg.Done()
			for time.Since(start) < duration {
				n, err := stream.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("Stream read error: %v", err)
					}
					break
				}
				totalBytes += int64(n)
			}
		}(stream)
	}
	wg.Wait()

	elapsed := time.Since(start).Seconds()
	throughputMbps := (float64(totalBytes) * 8 / elapsed) / 1e6
	fmt.Printf("Test Duration: %.2f seconds\n", elapsed)
	fmt.Printf("Total Data Received: %.2f MB\n", float64(totalBytes)/(1024*1024))
	fmt.Printf("Throughput: %.2f Mbps\n", throughputMbps)
	fmt.Printf("Window Size: %d bytes\n", windowSize)
	fmt.Printf("Buffer Size: %d bytes\n", bufferSize)
}

func main() {
	mode := flag.String("mode", "client", "Operation mode: 'server' or 'client'")
	addr := flag.String("addr", "localhost:5111", "Address to listen on server or connect to client")
	duration := flag.Duration("t", 10*time.Second, "Test duration for client mode (e.g., 10s)")
	windowSize := flag.Int("w", 53600000, "Flow control window size in bytes")
	bufferSize := flag.Int("b", 32*1024, "Buffer size in bytes for read/write operations")
	flag.Parse()

	if *mode == "server" {
		runServer(*addr, *windowSize, *bufferSize)
	} else {
		runClient(*addr, *duration, *windowSize, *bufferSize)
	}
}
