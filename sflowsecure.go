/* sflowsecure - one-way UDP encrypted tunnel */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

const (
	ivSizeBytes  = 16
	tagSizeBytes = 16
	maxUDPSize   = 8192
	// The per-session overhead is only about 120 bytes, so we can safely set a
	// number for the maxSessions that is enough for the largest known sFlow
	// deployments, (even if those deployments are very unlikely to ever push
	// all their agent feeds through one sflowsecure tunnel).
	maxSessions = 1000000
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
	sessions map[uint64]*SessionState
}

func NewAntiReplayTracker() *AntiReplayTracker {
	return &AntiReplayTracker{sessions: make(map[uint64]*SessionState)}
}

func (t *AntiReplayTracker) ValidateAndStep(sessionPrefix uint64, seq uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessions[sessionPrefix]
	if !exists {
		if len(t.sessions) >= maxSessions {
			// If we legitimately want this many sender sessions, then increase
			// the value of maxSessions and recompile, but if this is some kind
			// of exhaustion-attack then simply exiting so that the receiver is
			// restarted by systemd (after a short pause) is considered an acceptable
			// way of limiting the damage. At least the attack cannot grow memory
			// usage indefinitely or saturate a CPU core. Note that the systemd
			// unit file is exected to wait for a second or two and then restart
			// the service.
			log.Printf("Maximum session count reached (%d). Exiting.", maxSessions)
			os.Exit(1)
		}
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

	// Generate a unique 8-byte session prefix for process lifecycle
	var sessionPrefixBuf [8]byte
	if _, err := rand.Read(sessionPrefixBuf[:]); err != nil {
		log.Fatalf("Failed to securely seed session metadata: %v", err)
	}
	sessionPrefix := binary.BigEndian.Uint64(sessionPrefixBuf[:])
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
		// require enough headroom to add the header and still stay under the maxUDPSize,
		// because the receiver will assume that anything filling the buffer was larger
		// and has been truncated.
		// We could switch to rcvmsg() to know the truncation flag from the
		// kernel but this way is OK too since we should never get an sFlow datagram
		// that is anything close to this limit. The standard suggests 1400 bytes as
		// the max size to reduce the liklihood of any fragmentation in transit.
		if n > (maxUDPSize - tagSizeBytes - ivSizeBytes - 1) {
			log.Printf("Incoming datagram too large.")
			continue
		}

		// Calculate precise counter metrics
		currentCount := atomic.AddUint64(&packetCounter, 1) - 1

		// Inline structure formatting for the 16-byte nonce
		binary.BigEndian.PutUint64(iv[0:8], sessionPrefix)
		binary.BigEndian.PutUint64(iv[8:16], currentCount)

		// Pack unencrypted 16-byte nonce straight onto the front of the write window
		copy(writeBuf[0:ivSizeBytes], iv)

		// Encrypt in-place using direct hardware mapping (AVX/AES-NI)
		// Destination window bounds point safely behind the 16-byte header offset
		encryptedPayload := aesgcm.Seal(writeBuf[ivSizeBytes:ivSizeBytes], iv, readBuf[:n], nil)

		totalWireBytes := ivSizeBytes + len(encryptedPayload)
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
		if n >= maxUDPSize {
			continue // Discard anything we regard as too big.
			// Note that we assume anything exactly filling the read buffer
			// was truncated and ignore it too.
		}

		if n < (ivSizeBytes + tagSizeBytes) {
			continue // Discard corrupt microscopic fragments instantly
		}

		// Execute AEAD block decryption using writeBuf as an unallocated target window
		iv := readBuf[0:ivSizeBytes]
		ciphertextAndTag := readBuf[ivSizeBytes:n]
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
		sessionPrefix := binary.BigEndian.Uint64(readBuf[0:8])
		packetSequence := binary.BigEndian.Uint64(readBuf[8:16])
		if !replayTracker.ValidateAndStep(sessionPrefix, packetSequence) {
			continue // Drop replayed attack datagrams completely before wasting CPU on encryption math
		}

		// Pass verified telemetry payload down the chain to local consumers
		_, _ = connOut.Write(plaintext)
	}
}

// --- Bootstrap Engine ---

func main() {
	mode := os.Getenv("SFLOWSECURE_MODE")
	if mode != "sender" && mode != "receiver" {
		fmt.Println("Error: Invalid configuration state. A valid execution mode specification is required.")
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
	listen := os.Getenv("SFLOWSECURE_LISTEN")
	if listen == "" {
		log.Fatal("Fatal: SFLOWSECURE_LISTEN environment variable is not configured.")
	}
	forward := os.Getenv("SFLOWSECURE_FORWARD")
	if forward == "" {
		log.Fatal("Fatal: SFLOWSECURE_FORWARD environment variable is not configured.")
	}
	if mode == "sender" {
		runSender(listen, forward, key)
	} else {
		runReceiver(listen, forward, key)
	}
}

