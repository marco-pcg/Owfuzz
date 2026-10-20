// SPDX-License-Identifier: GPL-3.0-or-later
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"owfuzz/protocol"
	"owfuzz/wifi"
)

type Event struct {
	Sequence  uint64 `json:"sequence"`
	Direction string `json:"direction"`
	State     State  `json:"state,omitempty"`
	LinkType  uint32 `json:"link_type"`
	Channel   int    `json:"channel,omitempty"`
	Data      []byte `json:"data"`
	Error     string `json:"error,omitempty"`
}
type Runner struct {
	Controller        *Controller
	Receiver          protocol.Receiver
	Sender            protocol.Sender
	Mutation          protocol.Mutator
	Limit             uint64
	Log               io.Writer
	StatePath         string
	ContinueMalformed bool
	Sent              uint64
	BeaconInterval    time.Duration
	Extra             func() (protocol.Packet, error)
}

func (r *Runner) send(ctx context.Context, p protocol.Packet) error {
	if e := protocol.Deliver(ctx, r.Sender, p); e != nil {
		return e
	}
	r.Sent++
	if r.Log != nil {
		return json.NewEncoder(r.Log).Encode(Event{Sequence: r.Sent, Direction: "send", State: r.Controller.State, LinkType: p.LinkType, Channel: p.Channel, Data: p.Data})
	}
	return nil
}
func (r *Runner) emit(ctx context.Context, packets []protocol.Packet) error {
	for _, p := range packets {
		if r.Mutation != nil {
			if e := r.Mutation(&r.Controller.Context, &p); e != nil {
				return e
			}
		}
		if e := r.send(ctx, p); e != nil {
			return e
		}
		if r.Extra != nil {
			extra, e := r.Extra()
			if e != nil {
				return e
			}
			if e = r.send(ctx, extra); e != nil {
				return e
			}
		}
	}
	return nil
}
func (r *Runner) Run(ctx context.Context) (result error) {
	if r.Controller == nil || r.Receiver == nil || r.Sender == nil {
		return errors.New("controller/receiver/sender required")
	}
	defer func() { result = errors.Join(result, r.SaveState()) }()
	initial, e := r.Controller.Initial()
	if e != nil {
		return e
	}
	if e = r.emit(ctx, initial); e != nil {
		return e
	}
	lastBeacon := time.Now()
	for i := uint64(0); r.Limit == 0 || i < r.Limit; {
		receiveCtx := ctx
		cancel := func() {}
		beacon := r.BeaconInterval > 0 && r.Controller.Context.Role == "ap"
		if beacon {
			if time.Since(lastBeacon) >= r.BeaconInterval {
				packets, e := r.Controller.Initial()
				if e != nil {
					return e
				}
				if e = r.emit(ctx, packets); e != nil {
					return e
				}
				lastBeacon = time.Now()
			}
			receiveCtx, cancel = context.WithTimeout(ctx, time.Until(lastBeacon.Add(r.BeaconInterval)))
		}
		p, e := r.Receiver.Receive(receiveCtx)
		cancel()
		if errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil && beacon {
			continue
		}
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return e
		}
		i++
		out, e := r.Controller.Handle(p)
		if r.Log != nil {
			event := Event{Sequence: i, Direction: "receive", State: r.Controller.State, LinkType: p.LinkType, Channel: p.Channel, Data: p.Data}
			if e != nil {
				event.Error = e.Error()
			}
			if le := json.NewEncoder(r.Log).Encode(event); le != nil {
				return le
			}
		}
		if e != nil {
			if r.ContinueMalformed {
				continue
			}
			return e
		}
		if e = r.emit(ctx, out); e != nil {
			return e
		}
	}
	return nil
}

// State files contain diagnostic progress, not WPA key material. They are not
// handshake-resume checkpoints; authentication must restart with fresh peer state.
func (r *Runner) SaveState() error {
	if r.StatePath == "" {
		return nil
	}
	b, e := json.MarshalIndent(struct {
		State     State     `json:"state"`
		Sent      uint64    `json:"sent"`
		Iteration uint64    `json:"iteration"`
		Updated   time.Time `json:"updated"`
	}{r.Controller.State, r.Sent, r.Controller.Context.Iteration, time.Now().UTC()}, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(r.StatePath, append(b, '\n'), 0600)
}

// Replay runs packet captures through independent mutation and send strategies.
func Replay(ctx context.Context, receiver protocol.Receiver, sender protocol.Sender, c *protocol.Context, m protocol.Mutator, limit uint64, log io.Writer) error {
	for i := uint64(0); limit == 0 || i < limit; i++ {
		p, e := receiver.Receive(ctx)
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return e
		}
		c.Iteration = i
		if e = m(c, &p); e != nil {
			return e
		}
		if e = protocol.Deliver(ctx, sender, p); e != nil {
			return e
		}
		if log != nil {
			if e = json.NewEncoder(log).Encode(Event{Sequence: i, Direction: "replay", LinkType: p.LinkType, Data: p.Data}); e != nil {
				return e
			}
		}
	}
	return nil
}

// Forward implements transparent two-interface packet forwarding. Address/key
// spoofing is deliberately not inferred; encrypted frames stay encrypted.
func Forward(ctx context.Context, from protocol.Receiver, to protocol.Sender, limit uint64) error {
	for i := uint64(0); limit == 0 || i < limit; i++ {
		p, e := from.Receive(ctx)
		if e != nil {
			return e
		}
		if p.LinkType == protocol.WiFi {
			if _, e = wifi.Parse(p.Data); e != nil {
				continue
			}
		}
		p.Channel = 0
		if e = protocol.Deliver(ctx, to, p); e != nil {
			return fmt.Errorf("forward: %w", e)
		}
	}
	return nil
}
