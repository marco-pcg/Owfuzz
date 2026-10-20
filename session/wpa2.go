// SPDX-License-Identifier: GPL-3.0-or-later
package session

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"owfuzz/protocol"
	"owfuzz/wifi"
)

// PMK derives the WPA2 PSK. A 64-hex-digit value is an already derived PSK.
func PMK(pass, ssid string) ([]byte, error) {
	if len(ssid) > 32 {
		return nil, errors.New("SSID exceeds 32 bytes")
	}
	if len(pass) == 64 {
		b, e := hex.DecodeString(pass)
		if e == nil {
			return b, nil
		}
	}
	if len(pass) < 8 || len(pass) > 63 {
		return nil, errors.New("WPA2 password must be 8..63 bytes or 64 hex digits")
	}
	out := make([]byte, 0, 40)
	for block := uint32(1); len(out) < 32; block++ {
		s := append([]byte(ssid), 0, 0, 0, 0)
		binary.BigEndian.PutUint32(s[len(s)-4:], block)
		h := hmac.New(sha1.New, []byte(pass))
		h.Write(s)
		u := h.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < 4096; i++ {
			h.Reset()
			h.Write(u)
			u = h.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:32], nil
}
func ptk(pmk []byte, a, b protocol.MAC, anonce, snonce []byte) []byte {
	macs := append([]byte(nil), a[:]...)
	if bytes.Compare(a[:], b[:]) > 0 {
		macs = append([]byte(nil), b[:]...)
		macs = append(macs, a[:]...)
	} else {
		macs = append(macs, b[:]...)
	}
	if bytes.Compare(anonce, snonce) > 0 {
		macs = append(macs, snonce...)
		macs = append(macs, anonce...)
	} else {
		macs = append(macs, anonce...)
		macs = append(macs, snonce...)
	}
	out := make([]byte, 0, 80)
	for counter := byte(0); len(out) < 64; counter++ {
		h := hmac.New(sha1.New, pmk)
		h.Write([]byte("Pairwise key expansion\x00"))
		h.Write(macs)
		h.Write([]byte{counter})
		out = append(out, h.Sum(nil)...)
	}
	return out[:64]
}

// AESWrap implements RFC 3394. It is used only for WPA2 key-data serialization.
func AESWrap(key, plain []byte) ([]byte, error) {
	if len(plain) < 16 || len(plain)%8 != 0 {
		return nil, errors.New("key-wrap input must be >=16 and multiple of 8")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a := []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	r := append([]byte(nil), plain...)
	n := len(r) / 8
	tmp := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(tmp, a)
			copy(tmp[8:], r[(i-1)*8:i*8])
			block.Encrypt(tmp, tmp)
			v := binary.BigEndian.Uint64(tmp[:8]) ^ uint64(n*j+i)
			binary.BigEndian.PutUint64(a, v)
			copy(r[(i-1)*8:i*8], tmp[8:])
		}
	}
	return append(a, r...), nil
}
func AESUnwrap(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, errors.New("invalid key-wrap ciphertext")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a := append([]byte(nil), ciphertext[:8]...)
	r := append([]byte(nil), ciphertext[8:]...)
	n := len(r) / 8
	tmp := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			v := binary.BigEndian.Uint64(a) ^ uint64(n*j+i)
			binary.BigEndian.PutUint64(tmp, v)
			copy(tmp[8:], r[(i-1)*8:i*8])
			block.Decrypt(tmp, tmp)
			copy(a, tmp[:8])
			copy(r[(i-1)*8:i*8], tmp[8:])
		}
	}
	if !hmac.Equal(a, []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}) {
		return nil, errors.New("key-wrap integrity check failed")
	}
	return r, nil
}

type keyMessage struct {
	info             uint16
	replay           uint64
	nonce, data, raw []byte
}

func parseKey(b []byte) (keyMessage, error) {
	var k keyMessage
	if len(b) < 99 || b[1] != 3 || b[4] != 2 {
		return k, errors.New("not RSN EAPOL-Key")
	}
	if b[0] != 1 && b[0] != 2 {
		return k, errors.New("unsupported EAPOL version")
	}
	if int(binary.BigEndian.Uint16(b[2:]))+4 != len(b) {
		return k, errors.New("invalid EAPOL length")
	}
	k.info = binary.BigEndian.Uint16(b[5:])
	if k.info&7 != 2 || k.info&8 == 0 {
		return k, errors.New("only WPA2 pairwise SHA1/AES descriptors are supported")
	}
	if k.info&0x0c00 != 0 {
		return k, errors.New("EAPOL error/request flags")
	}
	n := int(binary.BigEndian.Uint16(b[97:]))
	if n != len(b)-99 {
		return k, errors.New("invalid key-data length")
	}
	k.replay = binary.BigEndian.Uint64(b[9:])
	k.nonce = append([]byte(nil), b[17:49]...)
	k.data = append([]byte(nil), b[99:]...)
	k.raw = append([]byte(nil), b...)
	return k, nil
}
func keyPacket(info uint16, replay uint64, nonce, data, kck []byte) []byte {
	b := make([]byte, 99+len(data))
	b[0] = 2
	b[1] = 3
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)-4))
	b[4] = 2
	binary.BigEndian.PutUint16(b[5:], info)
	binary.BigEndian.PutUint16(b[7:], 16)
	binary.BigEndian.PutUint64(b[9:], replay)
	copy(b[17:49], nonce)
	binary.BigEndian.PutUint16(b[97:], uint16(len(data)))
	copy(b[99:], data)
	if info&0x100 != 0 {
		sign(b, kck)
	}
	return b
}
func sign(b, kck []byte) {
	clear(b[81:97])
	h := hmac.New(sha1.New, kck)
	h.Write(b)
	copy(b[81:97], h.Sum(nil)[:16])
}
func validMIC(b, kck []byte) bool {
	if len(b) < 99 || len(kck) != 16 {
		return false
	}
	got := append([]byte(nil), b[81:97]...)
	copyPacket := append([]byte(nil), b...)
	sign(copyPacket, kck)
	return hmac.Equal(got, copyPacket[81:97])
}

type handshake struct {
	pmk, ptk, anonce, snonce []byte
	replay                   uint64
	lastM3                   []byte
	complete                 bool
}

func nonce(c *protocol.Context) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(c.Random() >> 24)
	}
	return b
}
func (h *handshake) start(c *protocol.Context) []byte {
	h.anonce = nonce(c)
	h.replay++
	h.complete = false
	h.ptk = nil
	return keyPacket(0x008a, h.replay, h.anonce, nil, nil)
}
func (h *handshake) handle(c *protocol.Context, b []byte) ([]byte, error) {
	k, e := parseKey(b)
	if e != nil {
		return nil, e
	}
	if c.Role == "ap" {
		if len(h.ptk) > 0 && len(h.lastM3) > 0 && k.info == 0x010a && k.replay+1 == h.replay && bytes.Equal(k.nonce, h.snonce) && validMIC(k.raw, h.ptk[:16]) {
			return append([]byte(nil), h.lastM3...), nil
		}
		if k.replay != h.replay {
			return nil, errors.New("EAPOL replay counter mismatch")
		}
		if k.info == 0x010a && len(h.anonce) == 32 && !h.complete {
			if bytes.Equal(k.nonce, make([]byte, 32)) {
				return nil, errors.New("zero SNonce")
			}
			candidate := ptk(h.pmk, c.BSSID, c.Destination, h.anonce, k.nonce)
			if !validMIC(k.raw, candidate[:16]) {
				return nil, errors.New("M2 MIC mismatch")
			}
			h.snonce = k.nonce
			h.ptk = candidate
			rsn := append([]byte{48, byte(len(wifi.RSN(c.Auth)))}, wifi.RSN(c.Auth)...)
			kde := []byte{221, 22, 0, 15, 172, 1, 1, 0}
			gtk := nonce(c)[:16]
			kde = append(kde, gtk...)
			plain := append(rsn, kde...)
			if len(plain)%8 != 0 {
				plain = append(plain, 221)
				for len(plain)%8 != 0 {
					plain = append(plain, 0)
				}
			}
			wrapped, e := AESWrap(candidate[16:32], plain)
			if e != nil {
				return nil, e
			}
			h.replay++
			h.lastM3 = keyPacket(0x13ca, h.replay, h.anonce, wrapped, candidate[:16])
			return append([]byte(nil), h.lastM3...), nil
		}
		if k.info == 0x030a && len(h.ptk) > 0 && !h.complete {
			if !validMIC(k.raw, h.ptk[:16]) {
				return nil, errors.New("M4 MIC mismatch")
			}
			h.complete = true
			return nil, nil
		}
		return nil, errors.New("unexpected WPA2 authenticator message")
	}
	if k.info == 0x008a {
		if bytes.Equal(k.nonce, make([]byte, 32)) {
			return nil, errors.New("zero ANonce")
		}
		if h.complete || k.replay < h.replay {
			return nil, errors.New("replayed M1")
		}
		if k.replay == h.replay && len(h.anonce) > 0 && !bytes.Equal(k.nonce, h.anonce) {
			return nil, errors.New("M1 changed nonce at same counter")
		}
		if k.replay > h.replay || len(h.snonce) == 0 {
			h.snonce = nonce(c)
		}
		h.anonce = k.nonce
		h.replay = k.replay
		h.ptk = ptk(h.pmk, c.BSSID, c.Source, h.anonce, h.snonce)
		rsn := append([]byte{48, byte(len(wifi.RSN(c.Auth)))}, wifi.RSN(c.Auth)...)
		return keyPacket(0x010a, h.replay, h.snonce, rsn, h.ptk[:16]), nil
	}
	if k.info == 0x13ca && len(h.ptk) > 0 {
		if h.complete && k.replay == h.replay && bytes.Equal(k.raw, h.lastM3) {
			return keyPacket(0x030a, h.replay, nil, nil, h.ptk[:16]), nil
		}
		if k.replay <= h.replay || !bytes.Equal(k.nonce, h.anonce) {
			return nil, errors.New("replayed/changed M3")
		}
		if !validMIC(k.raw, h.ptk[:16]) {
			return nil, errors.New("M3 MIC mismatch")
		}
		if _, e := AESUnwrap(h.ptk[16:32], k.data); e != nil {
			return nil, fmt.Errorf("M3: %w", e)
		}
		h.replay = k.replay
		h.lastM3 = append([]byte(nil), k.raw...)
		h.complete = true
		return keyPacket(0x030a, h.replay, nil, nil, h.ptk[:16]), nil
	}
	return nil, errors.New("unexpected WPA2 supplicant message")
}
