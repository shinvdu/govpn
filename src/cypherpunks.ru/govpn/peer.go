/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2016 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package govpn

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
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
	MaxBytesPerKey uint64 = 1 << 32
	// Heartbeat rate, relative to Timeout
	TimeoutHeartbeat = 4
	// Minimal valid packet length
	MinPktLength = 1 + 16 + 8
	// Padding byte
	PadByte = byte(0x80)
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
	// Statistics (they are at the beginning for correct int64 alignment)
	BytesIn         uint64
	BytesOut        uint64
	BytesPayloadIn  uint64
	BytesPayloadOut uint64
	FramesIn        uint64
	FramesOut       uint64
	FramesUnauth    uint64
	FramesDup       uint64
	HeartbeatRecv   uint64
	HeartbeatSent   uint64

	// Basic
	Addr string
	Id   *PeerId
	Conn io.Writer `json:"-"`

	// Traffic behaviour
	NoiseEnable bool
	CPR         int
	CPRCycle    time.Duration `json:"-"`
	Encless     bool
	MTU         int

	// Cryptography related
	Key         *[SSize]byte `json:"-"`
	NonceCipher *xtea.Cipher `json:"-"`
	nonceRecv   uint64
	nonceLatest uint64
	nonceOur    uint64
	NonceExpect uint64    `json:"-"`
	nonceWindow [5]uint64 // 257-bit sliding replay window
	nonceInit   bool

	// Timers
	Timeout       time.Duration `json:"-"`
	Established   time.Time
	LastPing      time.Time
	LastSent      time.Time
	willSentCycle time.Time

	// Receiver
	BusyR    sync.Mutex `json:"-"`
	bufR     []byte
	tagR     *[TagSize]byte
	keyAuthR *[SSize]byte
	pktSizeR int

	// Transmitter
	BusyT    sync.Mutex `json:"-"`
	bufT     []byte
	outT     []byte
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
	SliceZero(p.Key[:])
	SliceZero(p.bufR)
	SliceZero(p.bufT)
	SliceZero(p.keyAuthR[:])
	SliceZero(p.keyAuthT[:])
	p.BusyT.Unlock()
	p.BusyR.Unlock()
}

func (p *Peer) NonceExpectation(buf []byte) {
	binary.BigEndian.PutUint64(buf, p.NonceExpect)
	p.NonceCipher.Encrypt(buf, buf)
}

// nonceWindowSpan is the maximal serial distance accepted by the
// anti-replay window (the same bound as the old two-bucket map).
const nonceWindowSpan = 2 * NonceBucketSize

// nonceWindowShift shifts the replay bitmap by n serial positions
// (towards older entries), discarding those that fall out of the window.
func nonceWindowShift(w *[5]uint64, n int) {
	if n <= 0 {
		return
	}
	if n > nonceWindowSpan {
		*w = [5]uint64{}
		return
	}
	word := n / 64
	bit := uint(n % 64)
	var tmp [5]uint64
	if bit == 0 {
		for i := 4; i >= word; i-- {
			tmp[i] = w[i-word]
		}
	} else {
		for i := 4; i > word; i-- {
			tmp[i] = w[i-word]<<bit | w[i-word-1]>>(64-bit)
		}
		tmp[word] = w[0] << bit
	}
	*w = tmp
}

// nonceAccept records serial in the replay window and reports whether it
// is fresh.  Serial numbers normally advance by 2, but arbitrary values
// are handled as well.
func (p *Peer) nonceAccept(serial uint64) bool {
	if !p.nonceInit {
		p.nonceInit = true
		p.nonceLatest = serial
		p.nonceWindow = [5]uint64{1}
		return true
	}
	if serial > p.nonceLatest {
		if diff := serial - p.nonceLatest; diff > nonceWindowSpan {
			p.nonceWindow = [5]uint64{}
		} else {
			nonceWindowShift(&p.nonceWindow, int(diff))
		}
		p.nonceLatest = serial
		p.nonceWindow[0] |= 1
		return true
	}
	diff := p.nonceLatest - serial
	if diff > nonceWindowSpan {
		return false
	}
	word := diff / 64
	bit := uint(diff % 64)
	mask := uint64(1) << bit
	if p.nonceWindow[word]&mask != 0 {
		return false
	}
	p.nonceWindow[word] |= mask
	return true
}

func cprCycleCalculate(conf *PeerConf) time.Duration {
	if conf.CPR == 0 {
		return time.Duration(0)
	}
	rate := conf.CPR * 1 << 10
	if conf.Encless {
		rate /= EnclessEnlargeSize + conf.MTU
	} else {
		rate /= conf.MTU
	}
	return time.Second / time.Duration(rate)
}

func newPeer(isClient bool, addr string, conn io.Writer, conf *PeerConf, key *[SSize]byte) *Peer {
	now := time.Now()
	timeout := conf.Timeout

	cprCycle := cprCycleCalculate(conf)
	noiseEnable := conf.Noise
	if conf.CPR > 0 {
		noiseEnable = true
		timeout = cprCycle
	} else {
		timeout = timeout / TimeoutHeartbeat
	}

	bufSize := S20BS + 2*conf.MTU
	if conf.Encless {
		bufSize += EnclessEnlargeSize
		noiseEnable = true
	}
	peer := Peer{
		Addr: addr,
		Id:   conf.Id,
		Conn: conn,

		NoiseEnable: noiseEnable,
		CPR:         conf.CPR,
		CPRCycle:    cprCycle,
		Encless:     conf.Encless,
		MTU:         conf.MTU,

		Key:         key,
		NonceCipher: newNonceCipher(key),

		Timeout:     timeout,
		Established: now,
		LastPing:    now,

		bufR:     make([]byte, bufSize),
		bufT:     make([]byte, bufSize),
		tagR:     new([TagSize]byte),
		tagT:     new([TagSize]byte),
		keyAuthR: new([SSize]byte),
		keyAuthT: new([SSize]byte),
	}
	if !conf.Encless {
		// Tag + (payload + pad + nonce); the extra TagSize keeps this
		// safe even for unusually small MTU values.
		peer.outT = make(
			[]byte, TagSize,
			TagSize+conf.MTU+NonceSize+TagSize,
		)
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

// maxPayload returns the maximal payload that fits into a single wire
// packet for the current mode.  In noise/encless modes the packet is
// padded to MTU, so the trailing nonce (and, without encless, the
// Poly1305 tag) reduce the usable payload size.
func (p *Peer) maxPayload() int {
	if p.Encless {
		return p.MTU - NonceSize - 1
	}
	if p.NoiseEnable {
		return p.MTU - TagSize - NonceSize - 1
	}
	return p.MTU - 1
}

// Process incoming Ethernet packet.
// Encrypted and authenticated packets will be sent to the remote Peer
// side immediately.
func (p *Peer) EthProcess(data []byte) {
	if max := p.maxPayload(); len(data) > max {
		log.Println(
			"Data packet size", len(data), "exceeds effective maximum",
			max, "(MTU", p.MTU, "encless:", p.Encless,
			"noise:", p.NoiseEnable, ")", p,
		)
		return
	}
	p.now = time.Now()
	p.BusyT.Lock()

	// Zero size is a heartbeat packet.
	// Only the first SSize bytes of the Salsa20 scratch area have to be
	// zero: they become the Poly1305 one-time key.  The remaining part
	// of the header is discarded, so zeroing the whole buffer (several
	// kilobytes per packet) is unnecessary.
	SliceZero(p.bufT[:SSize])
	if len(data) == 0 {
		// If this heartbeat is necessary
		if !p.LastSent.Add(p.Timeout).Before(p.now) {
			p.BusyT.Unlock()
			return
		}
		p.bufT[S20BS+0] = PadByte
		p.HeartbeatSent++
	} else {
		// Copy payload to our internal buffer and we are ready to
		// accept the next one
		copy(p.bufT[S20BS:], data)
		p.bufT[S20BS+len(data)] = PadByte
		p.BytesPayloadOut += uint64(len(data))
	}

	if p.NoiseEnable && !p.Encless {
		p.frameT = p.bufT[S20BS : S20BS+p.MTU-TagSize]
	} else if p.Encless {
		p.frameT = p.bufT[S20BS : S20BS+p.MTU]
	} else {
		p.frameT = p.bufT[S20BS : S20BS+len(data)+1+NonceSize]
	}
	// Fill the part between the padding byte and the nonce with zeros
	// only when it actually goes on the wire (noise/encless modes).
	if p.NoiseEnable || p.Encless {
		padAt := len(data)
		end := len(p.frameT) - NonceSize
		if padAt+1 < end {
			SliceZero(p.frameT[padAt+1 : end])
		}
	}
	p.nonceOur += 2
	binary.BigEndian.PutUint64(p.frameT[len(p.frameT)-NonceSize:], p.nonceOur)
	p.NonceCipher.Encrypt(
		p.frameT[len(p.frameT)-NonceSize:],
		p.frameT[len(p.frameT)-NonceSize:],
	)
	var out []byte
	if p.Encless {
		var err error
		out, err = EnclessEncode(
			p.Key,
			p.frameT[len(p.frameT)-NonceSize:],
			p.frameT[:len(p.frameT)-NonceSize],
		)
		if err != nil {
			panic(err)
		}
		out = append(out, p.frameT[len(p.frameT)-NonceSize:]...)
	} else {
		salsa20.XORKeyStream(
			p.bufT[:S20BS+len(p.frameT)-NonceSize],
			p.bufT[:S20BS+len(p.frameT)-NonceSize],
			p.frameT[len(p.frameT)-NonceSize:],
			p.Key,
		)
		copy(p.keyAuthT[:], p.bufT[:SSize])
		poly1305.Sum(p.tagT, p.frameT, p.keyAuthT)
		atomic.AddUint64(&p.BytesOut, uint64(len(p.frameT)+TagSize))
		out = p.outT[:TagSize+len(p.frameT)]
		copy(out[:TagSize], p.tagT[:])
		copy(out[TagSize:], p.frameT)
	}
	p.FramesOut++

	if p.CPRCycle != time.Duration(0) {
		p.willSentCycle = p.LastSent.Add(p.CPRCycle)
		if p.willSentCycle.After(p.now) {
			time.Sleep(p.willSentCycle.Sub(p.now))
			p.now = p.willSentCycle
		}
	}

	p.LastSent = p.now
	p.Conn.Write(out)
	p.BusyT.Unlock()
}

func (p *Peer) PktProcess(data []byte, tap io.Writer, reorderable bool) bool {
	if len(data) < MinPktLength {
		return false
	}
	if !p.Encless && len(data) > len(p.bufR)-S20BS {
		return false
	}
	var out []byte
	p.BusyR.Lock()
	if p.Encless {
		var err error
		out, err = EnclessDecode(
			p.Key,
			data[len(data)-NonceSize:],
			data[:len(data)-NonceSize],
		)
		if err != nil {
			p.FramesUnauth++
			p.BusyR.Unlock()
			return false
		}
	} else {
		for i := 0; i < SSize; i++ {
			p.bufR[i] = 0
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
		out = p.bufR[S20BS : S20BS+len(data)-TagSize-NonceSize]
	}

	// Reject duplicates and packets that fell out of the replay window.
	p.NonceCipher.Decrypt(
		data[len(data)-NonceSize:],
		data[len(data)-NonceSize:],
	)
	p.nonceRecv = binary.BigEndian.Uint64(data[len(data)-NonceSize:])
	if reorderable {
		if !p.nonceAccept(p.nonceRecv) {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
	} else {
		if p.nonceRecv != p.NonceExpect {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
		p.NonceExpect += 2
		if p.nonceRecv > p.nonceLatest {
			p.nonceLatest = p.nonceRecv
		}
	}

	p.FramesIn++
	atomic.AddUint64(&p.BytesIn, uint64(len(data)))
	p.LastPing = time.Now()
	p.pktSizeR = bytes.LastIndexByte(out, PadByte)
	if p.pktSizeR == -1 {
		p.BusyR.Unlock()
		return false
	}
	// Validate the pad
	for i := p.pktSizeR + 1; i < len(out); i++ {
		if out[i] != 0 {
			p.BusyR.Unlock()
			return false
		}
	}

	if p.pktSizeR == 0 {
		p.HeartbeatRecv++
		p.BusyR.Unlock()
		return true
	}
	p.BytesPayloadIn += uint64(p.pktSizeR)
	tap.Write(out[:p.pktSizeR])
	p.BusyR.Unlock()
	return true
}
