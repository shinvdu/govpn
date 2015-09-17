/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2015 Sergey Matveev <stargrave@stargrave.org>

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
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agl/ed25519"
	"golang.org/x/crypto/xtea"
)

const (
	IDSize      = 128 / 8
	RefreshRate = 60 * time.Second
)

type PeerId [IDSize]byte

func (id PeerId) String() string {
	return hex.EncodeToString(id[:])
}

// Return human readable name of the peer.
// It equals either to peers/PEER/name file contents or PEER's hex.
func (id PeerId) MarshalJSON() ([]byte, error) {
	result := id.String()
	if name, err := ioutil.ReadFile(path.Join(PeersPath, result, "name")); err == nil {
		result = strings.TrimRight(string(name), "\n")
	}
	return []byte(`"` + result + `"`), nil
}

type cipherCache map[PeerId]*xtea.Cipher

var (
	PeersPath       string
	IDsCache        cipherCache
	cipherCacheLock sync.RWMutex
	dummyConf       *PeerConf
)

// Initialize (pre-cache) available peers info.
func PeersInit(path string) {
	PeersPath = path
	IDsCache = make(map[PeerId]*xtea.Cipher)
	go func() {
		for {
			IDsCache.refresh()
			time.Sleep(RefreshRate)
		}
	}()
}

// Initialize dummy cache for client-side usage.
func PeersInitDummy(id *PeerId, conf *PeerConf) {
	IDsCache = make(map[PeerId]*xtea.Cipher)
	cipher, err := xtea.NewCipher(id[:])
	if err != nil {
		panic(err)
	}
	IDsCache[*id] = cipher
	dummyConf = conf
}

// Refresh IDsCache: remove disappeared keys, add missing ones with
// initialized ciphers.
func (cc cipherCache) refresh() {
	dir, err := os.Open(PeersPath)
	if err != nil {
		panic(err)
	}
	peerIds, err := dir.Readdirnames(0)
	if err != nil {
		panic(err)
	}
	available := make(map[PeerId]bool)
	for _, peerId := range peerIds {
		id, err := IDDecode(peerId)
		if err != nil {
			continue
		}
		available[*id] = true
	}

	cipherCacheLock.Lock()
	// Cleanup deleted ones from cache
	for k, _ := range cc {
		if _, exists := available[k]; !exists {
			delete(cc, k)
			log.Println("Cleaning key: ", k)
		}
	}
	// Add missing ones
	for peerId, _ := range available {
		if _, exists := cc[peerId]; !exists {
			log.Println("Adding key", peerId)
			cipher, err := xtea.NewCipher(peerId[:])
			if err != nil {
				panic(err)
			}
			cc[peerId] = cipher
		}
	}
	cipherCacheLock.Unlock()
}

// Try to find peer's identity (that equals to an encryption key)
// by taking first blocksize sized bytes from data at the beginning
// as plaintext and last bytes as cyphertext.
func (cc cipherCache) Find(data []byte) *PeerId {
	if len(data) < xtea.BlockSize*2 {
		return nil
	}
	buf := make([]byte, xtea.BlockSize)
	cipherCacheLock.RLock()
	for pid, cipher := range cc {
		cipher.Decrypt(buf, data[len(data)-xtea.BlockSize:])
		if subtle.ConstantTimeCompare(buf, data[:xtea.BlockSize]) == 1 {
			ppid := PeerId(pid)
			cipherCacheLock.RUnlock()
			return &ppid
		}
	}
	cipherCacheLock.RUnlock()
	return nil
}

func readIntFromFile(path string) (int, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}
	val, err := strconv.Atoi(strings.TrimRight(string(data), "\n"))
	if err != nil {
		return 0, err
	}
	return val, nil
}

// Get peer related configuration.
func (id *PeerId) Conf() *PeerConf {
	if dummyConf != nil {
		return dummyConf
	}
	conf := PeerConf{Id: id, NoiseEnable: false, CPR: 0}
	peerPath := path.Join(PeersPath, id.String())

	verPath := path.Join(peerPath, "verifier")
	keyData, err := ioutil.ReadFile(verPath)
	if err != nil {
		log.Println("Unable to read verifier:", verPath)
		return nil
	}
	if len(keyData) < ed25519.PublicKeySize*2 {
		log.Println("Verifier must be 64 hex characters long:", verPath)
		return nil
	}
	keyDecoded, err := hex.DecodeString(string(keyData[:ed25519.PublicKeySize*2]))
	if err != nil {
		log.Println("Unable to decode the key:", err.Error(), verPath)
		return nil
	}
	conf.DSAPub = new([ed25519.PublicKeySize]byte)
	copy(conf.DSAPub[:], keyDecoded)

	timeout := TimeoutDefault
	if val, err := readIntFromFile(path.Join(peerPath, "timeout")); err == nil {
		timeout = val
	}
	conf.Timeout = time.Second * time.Duration(timeout)

	if val, err := readIntFromFile(path.Join(peerPath, "noise")); err == nil && val == 1 {
		conf.NoiseEnable = true
	}
	if val, err := readIntFromFile(path.Join(peerPath, "cpr")); err == nil {
		conf.CPR = val
	}
	return &conf
}

// Decode identification string.
// It must be 32 hexadecimal characters long.
func IDDecode(raw string) (*PeerId, error) {
	if len(raw) != IDSize*2 {
		return nil, errors.New("ID must be 32 characters long")
	}
	idDecoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, errors.New("ID must contain hexadecimal characters only")
	}
	idP := new([IDSize]byte)
	copy(idP[:], idDecoded)
	id := PeerId(*idP)
	return &id, nil
}
