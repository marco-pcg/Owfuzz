// SPDX-License-Identifier: GPL-3.0-or-later
// Package app contains the testable CLI. No C fuzzer subprocess or shared library is used.
package app

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"owfuzz/capture"
	"owfuzz/modules"
	"owfuzz/protocol"
	"owfuzz/radio"
	"owfuzz/session"
	"owfuzz/study"
	"owfuzz/wifi"
)

type stringsFlag []string

func (v *stringsFlag) String() string     { return strings.Join(*v, ",") }
func (v *stringsFlag) Set(s string) error { *v = append(*v, s); return nil }

type options struct {
	family, frames, strategy, output, input, interfaces, channels, source, dest, bssid, ssid, auth, role, mode, password, log, state, payload, ieMode, config, inputFormat, targetIP, exchange string
	seed                                                                                                                                                                                       uint64
	count                                                                                                                                                                                      uint64
	timeout, interval                                                                                                                                                                          time.Duration
	list, help, skipMalformed                                                                                                                                                                  bool
	legacyType                                                                                                                                                                                 int
	ies                                                                                                                                                                                        stringsFlag
}

func Usage(w io.Writer) {
	fmt.Fprintln(w, `Owfuzz (Go): protocol fuzzing, PCAP replay, and interactive WiFi

  owfuzz --list-protocols
  owfuzz --protocol ethernet --frame arp_request --count 100 --seed 42 --output arp.pcap
  owfuzz --protocol 802.11 --frame all --strategy bitflip --count 41 --output wifi.pcap
  owfuzz --mode replay --input poc.pcap --output replay.pcap
  owfuzz --mode interactive --role ap --input requests.pcap --output responses.pcap
  owfuzz --mode interactive --role sta --interface mon0 --channel 1 --timeout 30s

Modes: campaign (default), replay, interactive, combined, mitm.
Strategies: none, bitflip, truncate, bytes, ie, attributes.
Use --interface explicitly for live I/O; without it packets go to PCAP/stdout.
--input accepts classic PCAP, legacy hex logs and Go JSONL; use --input-format.
Radiotap captures are decoded automatically.
--frame accepts comma-separated names or all (excludes unsupported entries).
--auth controls corpus advertisements; interactive sessions support OPEN_NONE and
WPA2_PSK_AES (--password required for WPA2). --exchange fuzz enables deliberately
malformed SAE/WEP/WPA/EAP responses without claiming authenticated security.
P2P/AWDL/mesh profiles also provide bounded packet-driven responders.
Legacy aliases: -i interface -m ap|sta -c channel -t destination -s source
-b bssid -S ssid -A auth -T 0|1|2|3 -r seed -f log -h.
--config reads the supported legacy INI sections; explicit flags take precedence.
--ie ID:HEX may repeat; --ie-mode append|replace|omit|duplicate|invalid-length.
--state saves progress only; it does not persist encryption keys or resume handshakes.
--interval limits send rate; --timeout cancels a run; Ctrl-C closes live sockets.
--log emits JSONL packet events (base64 data), separate from binary PCAP output.`)
}
func parse(args []string, stderr io.Writer) (options, error) { return parseOptions(args, stderr, true) }
func parseOptions(args []string, stderr io.Writer, loadConfig bool) (options, error) {
	var o options
	o.legacyType = -1
	f := flag.NewFlagSet("owfuzz", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.Usage = func() { Usage(stderr) }
	f.StringVar(&o.family, "protocol", "802.11", "protocol family")
	f.StringVar(&o.frames, "frame", "", "frame(s)")
	f.StringVar(&o.strategy, "strategy", "none", "mutation strategy")
	f.StringVar(&o.output, "output", "", "PCAP path (default stdout)")
	f.StringVar(&o.input, "input", "", "input capture/log")
	f.StringVar(&o.inputFormat, "input-format", "auto", "auto|pcap|hex|jsonl")
	f.StringVar(&o.targetIP, "target-ip", "", "IPv4 liveness check")
	f.StringVar(&o.targetIP, "I", "", "IPv4 liveness check")
	f.StringVar(&o.interfaces, "interface", "", "live interface(s), comma separated")
	f.StringVar(&o.channels, "channel", "1", "channel(s)")
	f.StringVar(&o.source, "source", "02:00:00:00:00:01", "source MAC")
	f.StringVar(&o.dest, "destination", "ff:ff:ff:ff:ff:ff", "target MAC")
	f.StringVar(&o.bssid, "bssid", "02:00:00:00:00:01", "BSSID")
	f.StringVar(&o.ssid, "ssid", "owfuzz", "SSID")
	f.StringVar(&o.auth, "auth", "OPEN_NONE", "authentication advertisement")
	f.StringVar(&o.role, "role", "ap", "AP/STA role")
	f.StringVar(&o.mode, "mode", "campaign", "execution mode")
	f.StringVar(&o.password, "password", "", "WPA2 password")
	f.StringVar(&o.exchange, "exchange", "strict", "strict or fuzz authentication")
	f.StringVar(&o.log, "log", "", "JSONL log")
	f.StringVar(&o.state, "state", "", "progress JSON")
	f.StringVar(&o.payload, "payload", "", "hex payload")
	f.StringVar(&o.ieMode, "ie-mode", "append", "information-element mode")
	f.StringVar(&o.config, "config", "", "legacy configuration")
	f.Uint64Var(&o.seed, "seed", 1, "uint32 seed")
	f.Uint64Var(&o.count, "count", 1, "packet/input limit (0 = EOF for replay/interactive)")
	f.DurationVar(&o.timeout, "timeout", 0, "run deadline")
	f.DurationVar(&o.interval, "interval", 0, "send interval")
	f.BoolVar(&o.list, "list-protocols", false, "list families")
	f.BoolVar(&o.help, "protocol-help", false, "help")
	f.BoolVar(&o.skipMalformed, "skip-malformed", true, "log/skip malformed interactive packets")
	f.Var(&o.ies, "ie", "ID:HEX extra IE")
	f.IntVar(&o.legacyType, "T", -1, "legacy test type")
	f.StringVar(&o.interfaces, "i", "", "interface")
	f.StringVar(&o.channels, "c", "1", "channel")
	f.StringVar(&o.role, "m", "ap", "role")
	f.StringVar(&o.source, "s", "02:00:00:00:00:01", "source")
	f.StringVar(&o.dest, "t", "ff:ff:ff:ff:ff:ff", "target")
	f.StringVar(&o.bssid, "b", "02:00:00:00:00:01", "bssid")
	f.StringVar(&o.ssid, "S", "owfuzz", "SSID")
	f.StringVar(&o.auth, "A", "OPEN_NONE", "auth")
	f.Uint64Var(&o.seed, "r", 1, "seed")
	f.StringVar(&o.log, "f", "", "log")
	f.BoolVar(&o.help, "h", false, "help")
	if e := f.Parse(args); e != nil {
		return o, e
	}
	if f.NArg() != 0 {
		return o, fmt.Errorf("unexpected argument %q", f.Arg(0))
	}
	if loadConfig && o.config != "" {
		cfg, e := readConfig(o.config)
		if e != nil {
			return o, e
		}
		f.Visit(func(v *flag.Flag) {
			if v.Name == "role" || v.Name == "m" {
				cfg.values["fuzz_mode"] = o.role
			}
		})
		explicitFrame, explicitMode := false, false
		f.Visit(func(v *flag.Flag) {
			if v.Name == "frame" {
				explicitFrame = true
			}
			if v.Name == "mode" {
				explicitMode = true
			}
		})
		role := cfg.values["fuzz_mode"]
		if role == "" {
			role = o.role
		}
		effective := o.mode
		if !explicitMode {
			switch cfg.values["test_type"] {
			case "0":
				effective = "replay"
			case "1":
				effective = "interactive"
			case "2":
				effective = "campaign"
			case "3":
				effective = "combined"
			}
		}
		section := "ap-frames"
		if role == "sta" {
			section = "sta-frames"
		}
		if (role == "ap" || role == "sta") && (effective == "campaign" || effective == "combined") && !explicitFrame {
			if selected, present := cfg.frames[section]; present && len(selected) == 0 {
				return o, errors.New("configuration has no enabled frames")
			}
		}
		return parseOptions(append(configArgs(cfg), args...), stderr, false)
	}
	explicitMode, explicitCount := false, false
	f.Visit(func(v *flag.Flag) {
		if v.Name == "mode" {
			explicitMode = true
		}
		if v.Name == "count" {
			explicitCount = true
		}
	})
	if o.legacyType >= 0 && !explicitMode {
		switch o.legacyType {
		case 0:
			o.mode = "replay"
		case 1:
			o.mode = "interactive"
		case 2:
			o.mode = "campaign"
		case 3:
			o.mode = "combined"
		default:
			return o, errors.New("-T must be 0..3")
		}
	}
	switch o.role {
	case "p2p", "awdl", "mesh":
		if o.family != "802.11" && o.family != o.role {
			return o, errors.New("role/protocol conflict")
		}
		o.family = o.role
		o.role = "ap"
	case "mitm":
		if !explicitMode {
			o.mode = "mitm"
		}
		o.role = "ap"
	}
	if !explicitCount && o.mode != "campaign" {
		o.count = 0
	}
	if o.seed > 0xffffffff {
		return o, errors.New("seed exceeds uint32")
	}
	if o.count > 1000000 {
		return o, errors.New("count exceeds 1000000")
	}
	if o.timeout < 0 || o.interval < 0 {
		return o, errors.New("negative duration")
	}
	return o, nil
}
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		Usage(stdout)
		return nil
	}
	if len(args) > 0 && args[0] == "study" {
		return study.Run(ctx, args[1:], stdout, stderr)
	}
	o, e := parse(args, stderr)
	if errors.Is(e, flag.ErrHelp) {
		return nil
	}
	if e != nil {
		return e
	}
	if o.help {
		Usage(stdout)
		return nil
	}
	r, e := modules.NewRegistry()
	if e != nil {
		return e
	}
	if o.list {
		for _, f := range r.List() {
			fmt.Fprintf(stdout, "%s (linktype %d):", f.Name, f.LinkType)
			for _, frame := range f.Frames {
				fmt.Fprintf(stdout, " %s", frame.Name)
				if frame.Unsupported != "" {
					fmt.Fprint(stdout, "[unsupported]")
				}
			}
			fmt.Fprintln(stdout)
		}
		return nil
	}
	if o.exchange != "strict" && o.exchange != "fuzz" {
		return errors.New("exchange must be strict or fuzz")
	}
	if o.inputFormat != "auto" && o.inputFormat != "pcap" && o.inputFormat != "hex" && o.inputFormat != "jsonl" {
		return errors.New("unknown input format")
	}
	var target net.IP
	if o.targetIP != "" {
		target = net.ParseIP(o.targetIP)
		if target == nil || target.To4() == nil {
			return errors.New("target-ip must be IPv4")
		}
	}
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}
	c := protocol.DefaultContext()
	if c.Source, e = protocol.ParseMAC(o.source); e != nil {
		return e
	}
	if c.Destination, e = protocol.ParseMAC(o.dest); e != nil {
		return e
	}
	if c.BSSID, e = protocol.ParseMAC(o.bssid); e != nil {
		return e
	}
	c.SSID = o.ssid
	c.Auth = o.auth
	c.Role = o.role
	c.RandomState = uint32(o.seed)
	if len(c.SSID) > 32 {
		return errors.New("SSID exceeds 32 bytes")
	}
	if c.Role != "ap" && c.Role != "sta" {
		return fmt.Errorf("unsupported role %q; specialized corpora use --protocol p2p|awdl|mesh", c.Role)
	}
	if e = validateAuth(c.Auth); e != nil {
		return e
	}
	c.Payload, e = hex.DecodeString(o.payload)
	if e != nil {
		return fmt.Errorf("payload: %w", e)
	}
	if len(c.Payload) > protocol.MaxPacket-64 {
		return errors.New("payload exceeds capacity")
	}
	opts := modules.IEOptions{Mode: o.ieMode}
	if o.config != "" {
		cfg, err := readConfig(o.config)
		if err != nil {
			return err
		}
		opts.Disabled = cfg.disabled
		opts.DisabledExtensions = cfg.disabledExtensions
	}
	switch o.ieMode {
	case "append", "replace", "omit", "duplicate", "invalid-length":
	default:
		return errors.New("unknown IE mode")
	}
	for _, v := range o.ies {
		key, value, ok := strings.Cut(v, ":")
		if !ok {
			return errors.New("IE must be ID:HEX")
		}
		id, e := strconv.ParseUint(key, 10, 8)
		if e != nil {
			return e
		}
		b, e := hex.DecodeString(value)
		if e != nil || len(b) > 255 {
			return errors.New("invalid IE bytes/length")
		}
		opts.Extra = append(opts.Extra, wifi.Element{ID: byte(id), Value: b})
	}
	c.User = opts
	channelStrings := strings.Split(o.channels, ",")
	channels := make([]int, len(channelStrings))
	for i, s := range channelStrings {
		channels[i], e = strconv.Atoi(s)
		if e != nil || channels[i] < 1 || channels[i] > 255 {
			return errors.New("channel outside 1..255")
		}
	}
	c.Channel = channels[0]
	if c.Channel == 0 {
		c.Channel = 1
	}
	if len(channels) > 1 {
		c.Channel = 0
	}
	f, e := r.Family(o.family)
	if e != nil {
		return e
	}
	m, e := modules.Strategy(o.strategy)
	if e != nil {
		return e
	}
	var frames []string
	if o.frames == "all" {
		for _, frame := range f.Frames {
			if frame.Unsupported == "" {
				frames = append(frames, frame.Name)
			}
		}
	} else if o.frames != "" {
		frames = strings.Split(o.frames, ",")
	} else {
		switch o.family {
		case "802.11":
			if o.role == "ap" {
				frames = []string{"beacon"}
			} else {
				frames = []string{"probe_request"}
			}
		default:
			frames = []string{f.Frames[0].Name}
		}
	}
	for _, name := range frames {
		frame, e := f.Frame(name)
		if e != nil {
			return e
		}
		if frame.Unsupported != "" {
			return fmt.Errorf("%w: %s", protocol.ErrUnsupported, frame.Unsupported)
		}
	}
	switch o.mode {
	case "campaign", "interactive", "combined", "replay", "mitm":
	default:
		return fmt.Errorf("unknown mode %q", o.mode)
	}
	if o.mode == "campaign" && o.count == 0 {
		return errors.New("campaign count must be positive")
	}
	if o.mode == "campaign" && o.input != "" {
		return errors.New("use replay or interactive with --input")
	}
	if o.interfaces != "" && o.output != "" {
		return errors.New("live --interface and --output are mutually exclusive; use --log")
	}
	if (o.mode == "interactive" || o.mode == "combined") && (len(strings.Split(o.interfaces, ",")) > 1 || len(channels) > 1) {
		return errors.New("interactive sessions require a single interface/channel")
	}
	var controller *session.Controller
	if o.mode == "interactive" || o.mode == "combined" {
		if f.Name != "802.11" {
			controller, e = session.NewProfile(f.Name, c)
		} else {
			switch o.exchange {
			case "strict":
				controller, e = session.New(c, o.password)
			case "fuzz":
				controller, e = session.NewFuzz(c)
			default:
				return errors.New("exchange must be strict or fuzz")
			}
		}

		if e != nil {
			return e
		}
		if o.input == "" && o.interfaces == "" {
			return errors.New("interactive mode requires --input or --interface")
		}
	}
	if o.mode == "replay" && o.input == "" {
		return errors.New("replay requires --input")
	}
	// Refuse aliases of the input and output/log/state before opening/truncating files.
	paths := []string{o.input, o.output, o.log, o.state}
	for i, a := range paths {
		if a == "" {
			continue
		}
		for _, b := range paths[i+1:] {
			if b != "" && samePath(a, b) {
				return errors.New("input/output/log/state paths must be distinct")
			}
		}
	}
	var input *os.File
	var receiver protocol.Receiver
	if o.input != "" {
		input, e = os.Open(o.input)
		if e != nil {
			return e
		}
		defer input.Close()
		buffered := bufio.NewReader(input)
		format := o.inputFormat
		if format == "auto" {
			prefix, _ := buffered.Peek(4)
			format = "hex"
			if len(prefix) == 4 {
				for _, magic := range []string{"\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4", "\x4d\x3c\xb2\xa1", "\xa1\xb2\x3c\x4d"} {
					if string(prefix) == magic {
						format = "pcap"
					}
				}
			}
			if len(prefix) > 0 && prefix[0] == '{' {
				format = "jsonl"
			}
		}
		inputLink := f.LinkType
		if format == "pcap" {
			reader, err := capture.NewReader(buffered)
			if err != nil {
				return err
			}
			receiver = reader
			inputLink = reader.LinkType()
		} else {
			receiver = capture.NewTextReader(buffered, f.LinkType, format == "jsonl")
		}
		if inputLink == protocol.Radiotap {
			inputLink = protocol.WiFi
		}
		if inputLink != f.LinkType {
			return errors.New("input/protocol link type mismatch")
		}
	}

	var log io.Writer
	if o.log != "" {
		file, e := os.OpenFile(o.log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer file.Close()
		log = file
	}
	if o.mode == "mitm" {
		if o.state != "" {
			return errors.New("mitm progress snapshots are unsupported; use --log")
		}
		return runForward(ctx, o, channels, f.LinkType, log, m)
	}
	var sender protocol.Sender
	if o.interfaces != "" {
		names := strings.Split(o.interfaces, ",")
		if len(channels) == 1 {
			n := channels[0]
			channels = make([]int, len(names))
			for i := range channels {
				channels[i] = n
			}
		}
		if len(channels) != len(names) {
			return errors.New("provide one channel or one per interface")
		}
		group, e := radio.OpenGroup(ctx, names, channels, f.LinkType)
		if e != nil {
			return e
		}
		defer group.Close()
		sender = group
		if receiver == nil {
			receiver = group
		}
		if o.output != "" {
			return errors.New("live --interface and --output are mutually exclusive; use --log to retain traffic")
		}
	}
	var output *os.File
	if sender == nil {
		w := stdout
		if o.output != "" {
			output, e = os.OpenFile(o.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if e != nil {
				return e
			}
			defer output.Close()
			w = output
		}
		sender, e = capture.NewWriter(w, f.LinkType)
		if e != nil {
			return e
		}
	}
	if target != nil {
		sender = &healthSender{Sender: sender, ip: target}
	}
	if o.interval > 0 {
		sender = &paced{Sender: sender, interval: o.interval}
	}
	switch o.mode {
	case "campaign":
		campaign := protocol.Campaign{Family: f, Frames: frames, Count: o.count, Channels: channels, Mutate: m, Context: c}
		campaign.OnPacket = func(i uint64, p protocol.Packet) error {
			if log != nil {
				if e := json.NewEncoder(log).Encode(session.Event{Sequence: i, Direction: "send", LinkType: p.LinkType, Channel: p.Channel, Data: p.Data}); e != nil {
					return e
				}
			}
			if o.state != "" {
				data, e := json.MarshalIndent(struct {
					Next   uint64 `json:"next_iteration"`
					Random uint32 `json:"random_state"`
					Family string `json:"family"`
				}{i + 1, campaign.Context.RandomState, f.Name}, "", "  ")
				if e != nil {
					return e
				}
				return os.WriteFile(o.state, append(data, '\n'), 0600)
			}
			return nil
		}
		e = campaign.Run(ctx, sender)
	case "replay":
		e = session.Replay(ctx, receiver, sender, &c, m, o.count, log)
	case "interactive", "combined":
		runner := session.Runner{Controller: controller, Receiver: receiver, Sender: sender, Mutation: m, Limit: o.count, Log: log, StatePath: o.state, ContinueMalformed: o.skipMalformed}
		if o.interfaces != "" {
			runner.BeaconInterval = 100 * time.Millisecond
		}
		if o.mode == "combined" {
			step := uint64(0)
			runner.Extra = func() (protocol.Packet, error) {
				c.Iteration = step
				packet, e := protocol.Generate(f, frames[step%uint64(len(frames))], &c, m)
				step++
				return packet, e
			}
		}
		e = runner.Run(ctx)
	}
	if e != nil {
		return e
	}
	if output != nil {
		return output.Sync()
	}
	return nil
}
func samePath(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	if aa == bb {
		return true
	}
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(sa, sb)
}
func validateAuth(s string) error {
	switch s {
	case "OPEN_NONE", "OPEN_WEP", "SHARE_WEP", "WPA_PSK_TKIP", "WPA_PSK_AES", "WPA_PSK_TKIP_AES", "WPA2_PSK_TKIP", "WPA2_PSK_AES", "WPA2_PSK_TKIP_AES", "EAP_8021X", "WPA3":
		return nil
	}
	return fmt.Errorf("unknown authentication %q", s)
}

type paced struct {
	protocol.Sender
	interval time.Duration
	last     time.Time
}

func (p *paced) Send(ctx context.Context, b protocol.Packet) error {
	if !p.last.IsZero() {
		timer := time.NewTimer(time.Until(p.last.Add(p.interval)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	e := p.Sender.Send(ctx, b)
	p.last = time.Now()
	return e
}
func runForward(ctx context.Context, o options, channels []int, link uint32, log io.Writer, mutation protocol.Mutator) error {
	names := strings.Split(o.interfaces, ",")
	if len(names) != 2 || names[0] == names[1] || o.input != "" || o.output != "" {
		return errors.New("mitm requires two distinct --interface names and no input/output PCAP")
	}
	if len(channels) == 1 {
		channels = append(channels, channels[0])
	}
	if len(channels) != 2 {
		return errors.New("mitm requires one/two channels")
	}
	a, e := radio.Open(ctx, names[0], channels[0], link)
	if e != nil {
		return e
	}
	defer a.Close()
	b, e := radio.Open(ctx, names[1], channels[1], link)
	if e != nil {
		return e
	}
	defer b.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	var toB protocol.Sender = &forwardSender{Sender: b, mutation: mutation, c: protocol.Context{RandomState: uint32(o.seed)}, log: log}
	var toA protocol.Sender = &forwardSender{Sender: a, mutation: mutation, c: protocol.Context{RandomState: uint32(o.seed) + 1}, log: log}
	if o.interval > 0 {
		toB = &paced{Sender: toB, interval: o.interval}
		toA = &paced{Sender: toA, interval: o.interval}
	}
	if o.targetIP != "" {
		ip := net.ParseIP(o.targetIP)
		toB = &healthSender{Sender: toB, ip: ip}
		toA = &healthSender{Sender: toA, ip: ip}
	}
	go func() { done <- session.Forward(ctx, a, toB, o.count) }()
	go func() { done <- session.Forward(ctx, b, toA, o.count) }()
	e = <-done
	cancel()
	<-done
	return e
}

type healthSender struct {
	protocol.Sender
	ip   net.IP
	next time.Time
}

func (s *healthSender) Send(ctx context.Context, p protocol.Packet) error {
	if time.Now().After(s.next) {
		if e := session.CheckAlive(ctx, s.ip, 2*time.Second); e != nil {
			return e
		}
		s.next = time.Now().Add(5 * time.Second)
	}
	return s.Sender.Send(ctx, p)
}

type forwardSender struct {
	protocol.Sender
	mutation protocol.Mutator
	c        protocol.Context
	log      io.Writer
}

func (s *forwardSender) Send(ctx context.Context, p protocol.Packet) error {
	if e := s.mutation(&s.c, &p); e != nil {
		return e
	}
	if e := protocol.Deliver(ctx, s.Sender, p); e != nil {
		return e
	}
	if s.log != nil {
		if e := json.NewEncoder(s.log).Encode(session.Event{Direction: "send", Sequence: s.c.Iteration, LinkType: p.LinkType, Data: p.Data}); e != nil {
			return e
		}
	}
	s.c.Iteration++
	return nil
}
