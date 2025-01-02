package main

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s server <port> [windowSizeBytes] [readDelayMs]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s client <host:port> <MB to send> [windowSizeBytes] [numStreams]\n", os.Args[0])
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		log.Fatalf("Unknown mode: %s\n", os.Args[1])
	}
}

// -----------------------------
// SERVER
// -----------------------------
func runServer() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s server <port> [windowSizeBytes] [readDelayMs]\n", os.Args[0])
	}
	port := os.Args[2]

	// Default flow-control window: 1 MB
	windowSizeBytes := uint64(1 << 20) // 1 MB = 1048576 bytes
	if len(os.Args) > 3 {
		ws, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			log.Fatalf("Invalid windowSizeBytes: %v", err)
		}
		windowSizeBytes = ws
	}

	// Optional read delay in ms (to force slower reading)
	readDelayMs := 0
	if len(os.Args) > 4 {
		delay, err := strconv.Atoi(os.Args[4])
		if err != nil {
			log.Fatalf("Invalid readDelayMs: %v", err)
		}
		readDelayMs = delay
	}

	addr := ":" + port

	// Create a self-signed cert
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("generateSelfSignedCert error: %v", err)
	}
	tlsCertKeyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("X509KeyPair error: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCertKeyPair},
		NextProtos:   []string{"quic-perf"},
	}

	cfg := &quic.Config{
		// Flow-control window for each stream
		InitialStreamReceiveWindow: windowSizeBytes,
		MaxStreamReceiveWindow:     windowSizeBytes,

		// For the entire connection
		InitialConnectionReceiveWindow: 4 * windowSizeBytes,
		MaxConnectionReceiveWindow:     4 * windowSizeBytes,
	}

	listener, err := quic.ListenAddr(addr, tlsConfig, cfg)
	if err != nil {
		log.Fatalf("ListenAddr error: %v", err)
	}
	log.Printf("[SERVER] Listening on %s (stream window = %d bytes, readDelay = %d ms)", addr, windowSizeBytes, readDelayMs)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			// If listener is closed, we can exit gracefully
			if errors.Is(err, io.EOF) {
				log.Println("[SERVER] Listener closed.")
				return
			}
			log.Fatalf("[SERVER] Accept error: %v", err)
		}
		go handleConnection(conn, readDelayMs)
	}
}

func handleConnection(conn quic.Connection, readDelayMs int) {
	log.Printf("[SERVER] New connection from %s", conn.RemoteAddr())

	// This server expects the client to open N parallel streams
	// We'll accept until the client stops or closes them
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Println("[SERVER] Connection closed by client.")
			} else {
				log.Printf("[SERVER] AcceptStream error: %v", err)
			}
			return
		}
		go handleStream(stream, readDelayMs)
	}
}

func handleStream(stream quic.Stream, readDelayMs int) {
	defer stream.Close()

	var totalBytes uint64
	buf := make([]byte, 64*1024)
	start := time.Now()

	for {
		n, err := stream.Read(buf)
		if n > 0 {
			totalBytes += uint64(n)
			if readDelayMs > 0 {
				time.Sleep(time.Duration(readDelayMs) * time.Millisecond)
			}
		}
		if err == io.EOF {
			// done reading
			break
		}
		if err != nil {
			log.Printf("[SERVER] Stream read error: %v", err)
			return
		}
	}

	elapsed := time.Since(start).Seconds()
	mb := float64(totalBytes) / (1024.0 * 1024.0)
	log.Printf("[SERVER] Stream finished: received %.2f MB in %.2f sec -> %.2f MB/s",
		mb, elapsed, mb/elapsed)
}

// -----------------------------
// CLIENT
// -----------------------------
func runClient() {
	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s client <host:port> <MB to send> [windowSizeBytes] [numStreams]\n", os.Args[0])
	}
	addr := os.Args[2]

	// total MB to send across all streams
	mbToSend, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil || mbToSend == 0 {
		log.Fatalf("Invalid <MB to send>: %v", os.Args[3])
	}
	totalBytesToSend := mbToSend << 20 // convert MB -> bytes

	// flow-control window
	windowSizeBytes := uint64(1 << 20) // default 1 MB
	if len(os.Args) > 4 {
		ws, err := strconv.ParseUint(os.Args[4], 10, 64)
		if err != nil {
			log.Fatalf("Invalid windowSizeBytes: %v", err)
		}
		windowSizeBytes = ws
	}

	// number of parallel streams
	numStreams := 1
	if len(os.Args) > 5 {
		ns, err := strconv.Atoi(os.Args[5])
		if err != nil {
			log.Fatalf("Invalid numStreams: %v", err)
		}
		numStreams = ns
	}

	// Create self-signed cert for the client
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("generateSelfSignedCert error: %v", err)
	}
	tlsCertKeyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("X509KeyPair error: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCertKeyPair},
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-perf"},
	}

	cfg := &quic.Config{
		InitialStreamReceiveWindow:     windowSizeBytes,
		MaxStreamReceiveWindow:         windowSizeBytes,
		InitialConnectionReceiveWindow: 4 * windowSizeBytes,
		MaxConnectionReceiveWindow:     4 * windowSizeBytes,
	}

	session, err := quic.DialAddr(context.Background(), addr, tlsConfig, cfg)
	if err != nil {
		log.Fatalf("[CLIENT] DialAddr error: %v", err)
	}
	log.Printf("[CLIENT] Connected to %s. Sending %d MB total, across %d stream(s)...",
		addr, mbToSend, numStreams)

	startTotal := time.Now()

	// We’ll split the total bytes among numStreams
	bytesPerStream := totalBytesToSend / uint64(numStreams)

	var wg sync.WaitGroup
	wg.Add(numStreams)

	var totalSentAllStreams uint64
	var mu sync.Mutex // protects totalSentAllStreams

	for i := 0; i < numStreams; i++ {
		go func(streamIndex int) {
			defer wg.Done()

			// Open a stream
			stream, err := session.OpenStreamSync(context.Background())
			if err != nil {
				log.Fatalf("[CLIENT] Stream open error: %v", err)
			}
			defer stream.Close()

			// If there is leftover (when totalBytesToSend not divisible)
			// let the last stream send the remainder
			myBytesToSend := bytesPerStream
			if streamIndex == numStreams-1 {
				alreadyAccountedFor := bytesPerStream * uint64(numStreams-1)
				myBytesToSend = totalBytesToSend - alreadyAccountedFor
			}

			sendBuf := make([]byte, 64*1024)
			var sentThisStream uint64

			for sentThisStream < myBytesToSend {
				// fill buffer with random data
				nRand, err := crand.Read(sendBuf)
				if err != nil || nRand != len(sendBuf) {
					log.Fatalf("[CLIENT] Random read error: %v", err)
				}
				// figure out how many bytes remain to hit totalBytesToSend
				remaining := myBytesToSend - sentThisStream
				if uint64(len(sendBuf)) > remaining {
					// only send the leftover portion
					_, err = stream.Write(sendBuf[:remaining])
					if err != nil {
						log.Fatalf("[CLIENT] Stream write error: %v", err)
					}
					sentThisStream += remaining
					break
				}

				n, err := stream.Write(sendBuf)
				if err != nil {
					log.Fatalf("[CLIENT] Stream write error: %v", err)
				}
				sentThisStream += uint64(n)
			}

			mu.Lock()
			totalSentAllStreams += sentThisStream
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	elapsedTotal := time.Since(startTotal).Seconds()

	mbSentAll := float64(totalSentAllStreams) / (1024 * 1024)
	log.Printf("[CLIENT] Sent %.2f MB total in %.2f seconds -> %.2f MB/s",
		mbSentAll, elapsedTotal, mbSentAll/elapsedTotal)
}

// -----------------------------
// Helper: Generate Self-Signed Cert
// -----------------------------
func generateSelfSignedCert() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour), // 1-day validity
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}
