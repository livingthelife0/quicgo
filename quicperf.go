package main

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

// Entry point
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s server <port> [windowSizeBytes]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s client <host:port> <MB to send> [windowSizeBytes]\n", os.Args[0])
		os.Exit(1)
	}
	mode := os.Args[1]
	switch mode {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		log.Fatalf("Unknown mode: %s\n", mode)
	}
}

// -----------------------------
// SERVER
// -----------------------------
func runServer() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s server <port> [windowSizeBytes]\n", os.Args[0])
	}
	port := os.Args[2]

	// Default QUIC flow-control window: 1 MB
	// 1 MB = 1048576 bytes
	windowSizeBytes := uint64(1 << 20) 
	if len(os.Args) > 3 {
		ws, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			log.Fatalf("Invalid windowSizeBytes: %v", err)
		}
		windowSizeBytes = ws
	}

	addr := ":" + port

	// Create self-signed cert
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Could not generate cert: %v", err)
	}
	tlsCertKeyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Failed to parse TLS cert: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCertKeyPair},
		NextProtos:   []string{"quic-perf"},
	}

	// Adjust QUIC flow-control windows
	cfg := &quic.Config{
		InitialStreamReceiveWindow:     windowSizeBytes,
		InitialConnectionReceiveWindow: 4 * windowSizeBytes, 
		MaxStreamReceiveWindow:         2 * windowSizeBytes, 
		MaxConnectionReceiveWindow:     8 * windowSizeBytes, 
	}

	listener, err := quic.ListenAddr(addr, tlsConfig, cfg)
	if err != nil {
		log.Fatalf("quic.ListenAddr error: %v", err)
	}
	log.Printf("[SERVER] Listening on %s with stream window = %d bytes", addr, windowSizeBytes)

	// Accept connections in a loop
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Fatalf("Listener accept error: %v", err)
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Connection) {
	log.Printf("[SERVER] Got new connection from %s", conn.RemoteAddr().String())

	// We assume the client opens exactly one stream to send data
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("[SERVER] AcceptStream error: %v", err)
		return
	}
	defer stream.Close()

	// Read data until EOF
	var totalBytes uint64
	buf := make([]byte, 64*1024)
	start := time.Now()

	for {
		n, err := stream.Read(buf)
		if n > 0 {
			totalBytes += uint64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[SERVER] Stream read error: %v", err)
			return
		}
	}

	elapsed := time.Since(start).Seconds()
	mb := float64(totalBytes) / (1024.0 * 1024.0)
	log.Printf("[SERVER] Received %.2f MB in %.2f sec -> %.2f MB/s",
		mb, elapsed, mb/elapsed)
}

// -----------------------------
// CLIENT
// -----------------------------
func runClient() {
    if len(os.Args) < 4 {
        log.Fatalf("Usage: %s client <host:port> <duration in seconds> [windowSizeBytes]\n", os.Args[0])
    }
    addr := os.Args[2]

    // Parse duration in seconds
    durationSeconds, err := strconv.Atoi(os.Args[3])
    if err != nil || durationSeconds <= 0 {
        log.Fatalf("Invalid duration: %v", os.Args[3])
    }

    // Default buffer size
    windowSizeBytes := uint64(1 << 20) 
    if len(os.Args) > 4 {
        ws, err := strconv.ParseUint(os.Args[4], 10, 64)
        if err != nil {
            log.Fatalf("Invalid windowSizeBytes: %v", err)
        }
        windowSizeBytes = ws
    }

    // Create QUIC client
    certPEM, keyPEM, err := generateSelfSignedCert()
    if err != nil {
        log.Fatalf("Could not generate cert: %v", err)
    }
    tlsCertKeyPair, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        log.Fatalf("Failed to parse TLS cert: %v", err)
    }
    tlsConfig := &tls.Config{
        Certificates:       []tls.Certificate{tlsCertKeyPair},
        InsecureSkipVerify: true,
        NextProtos:         []string{"quic-perf"},
    }
    cfg := &quic.Config{
        MaxStreamReceiveWindow:         windowSizeBytes,
        MaxConnectionReceiveWindow:     4 * windowSizeBytes,
        InitialStreamReceiveWindow:     windowSizeBytes,
        InitialConnectionReceiveWindow: 4 * windowSizeBytes,
    }

    session, err := quic.DialAddr(context.Background(), addr, tlsConfig, cfg)
    if err != nil {
        log.Fatalf("[CLIENT] Failed to dial %s: %v", addr, err)
    }
    stream, err := session.OpenStreamSync(context.Background())
    if err != nil {
        log.Fatalf("[CLIENT] OpenStreamSync error: %v", err)
    }

    log.Printf("[CLIENT] Connected to %s. Sending data for %d seconds...", addr, durationSeconds)

    // Send random data for the specified duration
    sendBuf := make([]byte, 64*1024) 
    start := time.Now()
    totalSent := uint64(0)

    for time.Since(start).Seconds() < float64(durationSeconds) {
        // Fill the buffer with random data
        _, err := crand.Read(sendBuf)
        if err != nil {
            log.Fatalf("[CLIENT] Random read error: %v", err)
        }

        // Write data to the stream
        n, err := stream.Write(sendBuf)
        if err != nil {
            log.Fatalf("[CLIENT] Stream write error: %v", err)
        }
        totalSent += uint64(n)
    }

    elapsed := time.Since(start).Seconds()
    mb := float64(totalSent) / (1024.0 * 1024.0)
    log.Printf("[CLIENT] Sent %.2f MB in %.2f seconds -> %.2f MB/s", mb, elapsed, mb/elapsed)

    // Close the stream to signal end of data
    if err := stream.Close(); err != nil {
        log.Printf("[CLIENT] Stream close error: %v", err)
    }
}

func generateSelfSignedCert() ([]byte, []byte, error) {
	// Generate a simple RSA key
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	derBytes, err := x509.CreateCertificate(crand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// PEM-encode
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}
