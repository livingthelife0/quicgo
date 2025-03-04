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
	"time"

	"github.com/quic-go/quic-go"
)

// generateTLSConfig creates a self-signed TLS configuration for the server.
func generateTLSConfig() *tls.Config {
	// Generate a private key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create a template for a self-signed certificate.
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-iperf-example"},
	}
}

// runServer starts a QUIC server that continuously writes data to any connected client.
func runServer(addr string, windowSize int, bufferSize int) {
	// Create the QUIC configuration.
	quicConfig := &quic.Config{
		// Uncomment the following lines to apply the window size to flow control:
		// InitialStreamReceiveWindow:    uint64(windowSize),
		// InitialConnectionReceiveWindow:  uint64(windowSize),
	}

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), quicConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Server listening on %s", addr)

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go func(sess quic.Session) {
			for {
				stream, err := sess.AcceptStream(context.Background())
				if err != nil {
					log.Println("Stream accept error:", err)
					return
				}
				go func(stream quic.Stream) {
					// Use the bufferSize flag to allocate the write buffer.
					buf := make([]byte, bufferSize)
					for {
						_, err := stream.Write(buf)
						if err != nil {
							log.Println("Stream write error:", err)
							return
						}
					}
				}(stream)
			}
		}(sess)
	}
}

// runClient connects to the QUIC server, reads data for the specified duration,
// and then calculates and prints the throughput.
func runClient(addr string, duration time.Duration, windowSize int, bufferSize int) {
	quicConfig := &quic.Config{
		// Optionally, set flow control parameters on the client:
		// InitialStreamReceiveWindow:    uint64(windowSize),
		// InitialConnectionReceiveWindow:  uint64(windowSize),
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-iperf-example"},
	}

	session, err := quic.DialAddr(addr, tlsConf, quicConfig)
	if err != nil {
		log.Fatal(err)
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	var totalBytes int64 = 0
	// Use the bufferSize flag to allocate the read buffer.
	buf := make([]byte, bufferSize)

	for {
		if time.Since(start) > duration {
			break
		}
		n, err := stream.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println("Stream read error:", err)
			}
			break
		}
		totalBytes += int64(n)
	}

	elapsed := time.Since(start).Seconds()
	throughputMbps := (float64(totalBytes) * 8 / elapsed) / 1e6 // convert to Mbps
	fmt.Printf("Test Duration: %.2f seconds\n", elapsed)
	fmt.Printf("Total Data Received: %.2f MB\n", float64(totalBytes)/(1024*1024))
	fmt.Printf("Throughput: %.2f Mbps\n", throughputMbps)
}

func main() {
	mode := flag.String("mode", "client", "Operation mode: 'server' or 'client'")
	addr := flag.String("addr", "localhost:5111", "Address to listen on (server) or connect to (client)")
	duration := flag.Duration("t", 10*time.Second, "Duration of test (client mode), e.g., 10s")
	windowSize := flag.Int("w", 53600000, "Flow control window size in bytes")
	bufferSize := flag.Int("b", 32*1024, "Buffer size in bytes for read/write operations")
	flag.Parse()

	if *mode == "server" {
		runServer(*addr, *windowSize, *bufferSize)
	} else {
		runClient(*addr, *duration, *windowSize, *bufferSize)
	}
}
