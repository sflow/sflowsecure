/* sflowsecure - one-way UDP encrypted tunnel */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

const (
	ivSizeBytes  = 12
	tagSizeBytes = 16
	maxUDPSize   = 8192
)

var authFailures uint64

// --- Anti-Replay Sliding Window Implementation ---

type SessionState struct {
	windowMask      uint64
	maxSeenSequence uint64
	initialized     bool
}

type AntiReplayTracker struct {
	mu       sync.Mutex
	sessions map[uint32]*SessionState
}

func NewAntiReplayTracker() *AntiReplayTracker {
	return &AntiReplayTracker{sessions: make(map[uint32]*SessionState)}
}

func (t *AntiReplayTracker) ValidateAndStep(sessionPrefix uint32, seq uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessions[sessionPrefix]
	if !exists {
		state = &SessionState{}
		t.sessions[sessionPrefix] = state
	}

	if !state.initialized {
		state.maxSeenSequence = seq
		state.windowMask = 1
		state.initialized = true
		return true
	}

	if seq > state.maxSeenSequence {
		diff := seq - state.maxSeenSequence
		if diff >= 64 {
			state.windowMask = 1
		} else {
			state.windowMask <<= diff
			state.windowMask |= 1
		}
		state.maxSeenSequence = seq
		return true
	}

	// Out of order or old packet
	diff := state.maxSeenSequence - seq
	if diff >= 64 {
		return false // Too old, dropped behind trailing window edge
	}

	maskCheck := uint64(1) << diff
	if (state.windowMask & maskCheck) != 0 {
		return false // Duplicate packet
	}

	state.windowMask |= maskCheck
	return true
}

// --- Sender Node ---

func runSender(listenAddr, forwardAddrStr string, key []byte) {
	// Initialize hardware-accelerated AES-GCM block
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to initialize AES engine: %v", err)
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, ivSizeBytes)
	if err != nil {
		log.Fatalf("Failed to initialize GCM wrapper: %v", err)
	}

	// Generate a unique 4-byte session prefix for process lifecycle
	var sessionPrefixBuf [4]byte
	if _, err := rand.Read(sessionPrefixBuf[:]); err != nil {
		log.Fatalf("Failed to securely seed session metadata: %v", err)
	}
	sessionPrefix := binary.BigEndian.Uint32(sessionPrefixBuf[:])
	var packetCounter uint64

	// Bind listener socket to ingest clean local metrics stream
	lAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("Invalid local listening target: %v", err)
	}
	connIn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatalf("Failed to bind inbound port: %v", err)
	}
	defer connIn.Close()

	// Resolve destination public internet socket address
	fAddr, err := net.ResolveUDPAddr("udp", forwardAddrStr)
	if err != nil {
		log.Fatalf("Invalid remote forwarding destination: %v", err)
	}
	connOut, err := net.DialUDP("udp", nil, fAddr)
	if err != nil {
		log.Fatalf("Failed to open connection to target receiver: %v", err)
	}
	defer connOut.Close()

	log.Printf("Sender operational. Intercepting on %s -> Encrypting -> Streaming to %s", listenAddr, forwardAddrStr)

	// Pre-allocate zero-allocation buffer array windows
	readBuf := make([]byte, maxUDPSize)
	writeBuf := make([]byte, maxUDPSize)
	iv := make([]byte, ivSizeBytes)

	for {
		n, _, err := connIn.ReadFromUDP(readBuf)
		if err != nil {
			log.Printf("Read tracking fault: %v", err)
			continue
		}

		// Calculate precise counter metrics
		currentCount := atomic.AddUint64(&packetCounter, 1) - 1

		// Inline structure formatting for the 12-byte Counter IV
		binary.BigEndian.PutUint32(iv[0:4], sessionPrefix)
		binary.BigEndian.PutUint64(iv[4:12], currentCount)

		// Pack unencrypted 12-byte IV block straight onto the front of the write window
		copy(writeBuf[0:12], iv)

		// Encrypt in-place using direct hardware mapping (AVX/AES-NI)
		// Destination window bounds point safely behind the 12-byte header offset
		encryptedPayload := aesgcm.Seal(writeBuf[12:12], iv, readBuf[:n], nil)

		totalWireBytes := 12 + len(encryptedPayload)
		_, _ = connOut.Write(writeBuf[:totalWireBytes])
	}
}

// --- Receiver Node ---

func runReceiver(listenAddr, forwardAddrStr string, key []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to initialize AES engine: %v", err)
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, ivSizeBytes)
	if err != nil {
		log.Fatalf("Failed to initialize GCM wrapper: %v", err)
	}

	replayTracker := NewAntiReplayTracker()

	// Bind public socket interface to ingest raw telemetry packets
	lAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("Invalid internet intercept target: %v", err)
	}
	connIn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatalf("Failed to bind public internet ingress port: %v", err)
	}
	defer connIn.Close()

	// Resolve the target internal metric analyzer IP/Port
	fAddr, err := net.ResolveUDPAddr("udp", forwardAddrStr)
	if err != nil {
		log.Fatalf("Invalid internal metric destination target: %v", err)
	}
	connOut, err := net.DialUDP("udp", nil, fAddr)
	if err != nil {
		log.Fatalf("Failed to map pipeline output target socket: %v", err)
	}
	defer connOut.Close()

	log.Printf("Receiver operational. Ingesting from open internet on %s -> Validating & Decrypting -> Extracting cleartext metrics to %s", listenAddr, forwardAddrStr)

	readBuf := make([]byte, maxUDPSize)
	writeBuf := make([]byte, maxUDPSize)

	for {
		n, _, err := connIn.ReadFromUDP(readBuf)
		if err != nil {
			log.Printf("Ingress network fault: %v", err)
			continue
		}

		if n < ivSizeBytes+tagSizeBytes {
			continue // Discard corrupt microscopic fragments instantly
		}

		// Execute AEAD block decryption using writeBuf as an unallocated target window
		iv := readBuf[0:12]
		ciphertextAndTag := readBuf[12:n]
		plaintext, err := aesgcm.Open(writeBuf[:0], iv, ciphertextAndTag, nil)
		if err != nil {
			// rate limited logging for auth failures
			failures := atomic.AddUint64(&authFailures, 1)
			if failures%1000 == 1 {
				log.Printf(
					"Authentication failures: %d",
					failures,
				)
			}
			continue
		}

		// FAST FILTER: absolute offset extraction of the session prefix and counter directly from unencrypted IV
		sessionPrefix := binary.BigEndian.Uint32(readBuf[0:4])
		packetSequence := binary.BigEndian.Uint64(readBuf[4:12])
		if !replayTracker.ValidateAndStep(sessionPrefix, packetSequence) {
			continue // Drop replayed attack datagrams completely before wasting CPU on encryption math
		}

		// Pass verified telemetry payload down the chain to local consumers
		_, _ = connOut.Write(plaintext)
	}
}

// --- Bootstrap Engine ---

func main() {
	mode := flag.String("mode", "", "Execution lifecycle mapping: 'sender' or 'receiver'")
	listen := flag.String("listen", "127.0.0.1:6343", "Local binding listener target IP:Port string")
	forward := flag.String("forward", "127.0.0.1:6344", "Target destination ip:port matrix")
	flag.Parse()

	if *mode != "sender" && *mode != "receiver" {
		fmt.Println("Error: Invalid configuration state. A valid execution mode specification is required.")
		flag.Usage()
		os.Exit(1)
	}

	keyHex := os.Getenv("SFLOWSECURE_KEY")
	if keyHex == "" {
		log.Fatal("Fatal: SFLOWSECURE_KEY environment variable is not configured.")
	}
	key := []byte(keyHex)
	if len(key) != 32 {
		log.Fatalf("Fatal cryptographic configuration validation failure: The key string input length must be exactly 32 characters (256-bits). Current length detected: %d", len(key))
	}

	if *mode == "sender" {
		runSender(*listen, *forward, key)
	} else {
		runReceiver(*listen, *forward, key)
	}
}

