package govpn

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/xtea"
)

const (
	NonceSize       = 8
	NonceBucketSize = 128
	TagSize         = poly1305.TagSize
	// S20BS is Salsa20's internal blocksize in bytes
	S20BS = 64
	// Maximal amount of bytes transfered with single key (4 GiB)
	MaxBytesPerKey int64 = 1 << 32
	// Size of packet's size mark in bytes
	PktSizeSize = 2
	// Heartbeat rate, relative to Timeout
	TimeoutHeartbeat = 4
	// Minimal valid packet length
	MinPktLength = 2 + 16 + 8
)

func newNonceCipher(key *[32]byte) *xtea.Cipher {
	nonceKey := make([]byte, 16)
	salsa20.XORKeyStream(
		nonceKey,
		make([]byte, 32),
		make([]byte, xtea.BlockSize),
		key,
	)
	ciph, err := xtea.NewCipher(nonceKey)
	if err != nil {
		panic(err)
	}
	return ciph
}

type Peer struct {
	Addr string
	Id   *PeerId
	Conn io.Writer

	// Traffic behaviour
	NoiseEnable bool
	CPR         int
	CPRCycle    time.Duration `json:"-"`

	// Cryptography related
	Key          *[SSize]byte `json:"-"`
	NonceCipher  *xtea.Cipher `json:"-"`
	nonceRecv    uint64
	nonceLatest  uint64
	nonceOur     uint64
	NonceExpect  uint64 `json:"-"`
	nonceBucket0 map[uint64]struct{}
	nonceBucket1 map[uint64]struct{}
	nonceFound0  bool
	nonceFound1  bool
	nonceBucketN int32

	// Timers
	Timeout       time.Duration `json:"-"`
	Established   time.Time
	LastPing      time.Time
	LastSent      time.Time
	willSentCycle time.Time

	// Statistics
	BytesIn         int64
	BytesOut        int64
	BytesPayloadIn  int64
	BytesPayloadOut int64
	FramesIn        int
	FramesOut       int
	FramesUnauth    int
	FramesDup       int
	HeartbeatRecv   int
	HeartbeatSent   int

	// Receiver
	BusyR    sync.Mutex `json:"-"`
	bufR     []byte
	tagR     *[TagSize]byte
	keyAuthR *[SSize]byte
	pktSizeR uint16

	// Transmitter
	BusyT    sync.Mutex `json:"-"`
	bufT     []byte
	tagT     *[TagSize]byte
	keyAuthT *[SSize]byte
	frameT   []byte
	now      time.Time
}

func (p *Peer) String() string {
	return p.Id.String() + ":" + p.Addr
}

// Zero peer's memory state.
func (p *Peer) Zero() {
	p.BusyT.Lock()
	p.BusyR.Lock()
	sliceZero(p.Key[:])
	sliceZero(p.bufR)
	sliceZero(p.bufT)
	sliceZero(p.keyAuthR[:])
	sliceZero(p.keyAuthT[:])
	p.BusyT.Unlock()
	p.BusyR.Unlock()
}

func newPeer(isClient bool, addr string, conn io.Writer, conf *PeerConf, key *[SSize]byte) *Peer {
	now := time.Now()
	timeout := conf.Timeout

	cprCycle := cprCycleCalculate(conf.CPR)
	noiseEnable := conf.Noise
	if conf.CPR > 0 {
		noiseEnable = true
		timeout = cprCycle
	} else {
		timeout = timeout / TimeoutHeartbeat
	}

	peer := Peer{
		Addr: addr,
		Id:   conf.Id,
		Conn: conn,

		NoiseEnable: noiseEnable,
		CPR:         conf.CPR,
		CPRCycle:    cprCycle,

		Key:          key,
		NonceCipher:  newNonceCipher(key),
		nonceBucket0: make(map[uint64]struct{}, NonceBucketSize),
		nonceBucket1: make(map[uint64]struct{}, NonceBucketSize),

		Timeout:     timeout,
		Established: now,
		LastPing:    now,

		bufR:     make([]byte, S20BS+MTU+NonceSize),
		bufT:     make([]byte, S20BS+MTU+NonceSize),
		tagR:     new([TagSize]byte),
		tagT:     new([TagSize]byte),
		keyAuthR: new([SSize]byte),
		keyAuthT: new([SSize]byte),
	}
	if isClient {
		peer.nonceOur = 1
		peer.NonceExpect = 0 + 2
	} else {
		peer.nonceOur = 0
		peer.NonceExpect = 1 + 2
	}
	return &peer

}

// Process incoming Ethernet packet.
// ready channel is TAPListen's synchronization channel used to tell him
// that he is free to receive new packets. Encrypted and authenticated
// packets will be sent to remote Peer side immediately.
func (p *Peer) EthProcess(data []byte) {
	p.now = time.Now()
	p.BusyT.Lock()

	// Zero size is a heartbeat packet
	if len(data) == 0 {
		// If this heartbeat is necessary
		if !p.LastSent.Add(p.Timeout).Before(p.now) {
			p.BusyT.Unlock()
			return
		}
		p.bufT[S20BS+0] = byte(0)
		p.bufT[S20BS+1] = byte(0)
		p.HeartbeatSent++
	} else {
		// Copy payload to our internal buffer and we are ready to
		// accept the next one
		binary.BigEndian.PutUint16(
			p.bufT[S20BS:S20BS+PktSizeSize],
			uint16(len(data)),
		)
		copy(p.bufT[S20BS+PktSizeSize:], data)
		p.BytesPayloadOut += int64(len(data))
	}

	if p.NoiseEnable {
		p.frameT = p.bufT[S20BS : S20BS+MTU-TagSize]
	} else {
		p.frameT = p.bufT[S20BS : S20BS+PktSizeSize+len(data)+NonceSize]
	}
	p.nonceOur += 2
	binary.BigEndian.PutUint64(p.frameT[len(p.frameT)-NonceSize:], p.nonceOur)
	p.NonceCipher.Encrypt(
		p.frameT[len(p.frameT)-NonceSize:],
		p.frameT[len(p.frameT)-NonceSize:],
	)
	for i := 0; i < SSize; i++ {
		p.bufT[i] = byte(0)
	}
	salsa20.XORKeyStream(
		p.bufT[:S20BS+len(p.frameT)-NonceSize],
		p.bufT[:S20BS+len(p.frameT)-NonceSize],
		p.frameT[len(p.frameT)-NonceSize:],
		p.Key,
	)

	copy(p.keyAuthT[:], p.bufT[:SSize])
	poly1305.Sum(p.tagT, p.frameT, p.keyAuthT)

	atomic.AddInt64(&p.BytesOut, int64(len(p.frameT)+TagSize))
	p.FramesOut++

	if p.CPRCycle != time.Duration(0) {
		p.willSentCycle = p.LastSent.Add(p.CPRCycle)
		if p.willSentCycle.After(p.now) {
			time.Sleep(p.willSentCycle.Sub(p.now))
			p.now = p.willSentCycle
		}
	}

	p.LastSent = p.now
	p.Conn.Write(append(p.tagT[:], p.frameT...))
	p.BusyT.Unlock()
}

func (p *Peer) PktProcess(data []byte, tap io.Writer, reorderable bool) bool {
	p.BusyR.Lock()
	for i := 0; i < SSize; i++ {
		p.bufR[i] = byte(0)
	}
	copy(p.bufR[S20BS:], data[TagSize:])
	salsa20.XORKeyStream(
		p.bufR[:S20BS+len(data)-TagSize-NonceSize],
		p.bufR[:S20BS+len(data)-TagSize-NonceSize],
		data[len(data)-NonceSize:],
		p.Key,
	)

	copy(p.keyAuthR[:], p.bufR[:SSize])
	copy(p.tagR[:], data[:TagSize])
	if !poly1305.Verify(p.tagR, data[TagSize:], p.keyAuthR) {
		p.FramesUnauth++
		p.BusyR.Unlock()
		return false
	}

	// Check if received nonce is known to us in either of two buckets.
	// If yes, then this is ignored duplicate.
	// Check from the oldest bucket, as in most cases this will result
	// in constant time check.
	// If Bucket0 is filled, then it becomes Bucket1.
	p.NonceCipher.Decrypt(
		data[len(data)-NonceSize:],
		data[len(data)-NonceSize:],
	)
	p.nonceRecv = binary.BigEndian.Uint64(data[len(data)-NonceSize:])
	if reorderable {
		_, p.nonceFound0 = p.nonceBucket0[p.nonceRecv]
		_, p.nonceFound1 = p.nonceBucket1[p.nonceRecv]
		if p.nonceFound0 || p.nonceFound1 || p.nonceRecv+2*NonceBucketSize < p.nonceLatest {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
		p.nonceBucket0[p.nonceRecv] = struct{}{}
		p.nonceBucketN++
		if p.nonceBucketN == NonceBucketSize {
			p.nonceBucket1 = p.nonceBucket0
			p.nonceBucket0 = make(map[uint64]struct{}, NonceBucketSize)
			p.nonceBucketN = 0
		}
	} else {
		if p.nonceRecv != p.NonceExpect {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
		p.NonceExpect += 2
	}
	if p.nonceRecv > p.nonceLatest {
		p.nonceLatest = p.nonceRecv
	}

	p.FramesIn++
	atomic.AddInt64(&p.BytesIn, int64(len(data)))
	p.LastPing = time.Now()
	p.pktSizeR = binary.BigEndian.Uint16(p.bufR[S20BS : S20BS+PktSizeSize])

	if p.pktSizeR == 0 {
		p.HeartbeatRecv++
		p.BusyR.Unlock()
		return true
	}
	p.BytesPayloadIn += int64(p.pktSizeR)
	tap.Write(p.bufR[S20BS+PktSizeSize : S20BS+PktSizeSize+p.pktSizeR])
	p.BusyR.Unlock()
	return true
}
