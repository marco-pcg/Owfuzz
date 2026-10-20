// SPDX-License-Identifier: GPL-3.0-or-later
package capture

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"owfuzz/protocol"
)

type TextReader struct {
	scanner *bufio.Scanner
	link    uint32
	json    bool
}

func NewTextReader(r io.Reader, link uint32, jsonLines bool) *TextReader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 65536)
	return &TextReader{scanner: s, link: link, json: jsonLines}
}
func (r *TextReader) LinkType() uint32 { return r.link }
func (r *TextReader) Receive(ctx context.Context) (protocol.Packet, error) {
	for r.scanner.Scan() {
		if e := ctx.Err(); e != nil {
			return protocol.Packet{}, e
		}
		line := strings.TrimSpace(r.scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := protocol.Packet{LinkType: r.link}
		if r.json {
			var event struct {
				Direction string `json:"direction"`
				Link      uint32 `json:"link_type"`
				Data      []byte `json:"data"`
				Channel   int    `json:"channel"`
			}
			if e := json.Unmarshal([]byte(line), &event); e != nil {
				return p, e
			}
			switch event.Direction {
			case "send", "replay", "combined-fuzz":
			case "receive":
				continue
			default:
				return p, errors.New("unknown packet log direction")
			}
			p.Data = event.Data
			p.LinkType = event.Link
			p.Channel = event.Channel
			if p.LinkType != r.link {
				return p, errors.New("packet log link type mismatch")
			}
		} else {
			line = strings.NewReplacer("\\x", "", "\\X", "", "0x", "", "0X", "", " ", "", "\t", "", ",", "", ":", "").Replace(line)
			if len(line) > protocol.MaxPacket*2 {
				return p, errors.New("hex packet exceeds capacity")
			}
			var e error
			p.Data, e = hex.DecodeString(line)
			if e != nil {
				return p, e
			}
		}
		return p, p.Validate()
	}
	if e := r.scanner.Err(); e != nil {
		return protocol.Packet{}, e
	}
	return protocol.Packet{}, io.EOF
}
