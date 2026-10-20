// SPDX-License-Identifier: GPL-3.0-or-later
package app

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type config struct {
	values             map[string]string
	frames             map[string][]string
	interfaces         []string
	channels           []string
	disabled           map[byte]bool
	disabledExtensions map[byte]bool
}

func readConfig(path string) (config, error) {
	out := config{values: map[string]string{}, frames: map[string][]string{}, disabled: map[byte]bool{}, disabledExtensions: map[byte]bool{}}
	f, e := os.Open(path)
	if e != nil {
		return out, e
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1024), 65536)
	section := ""
	line := 0
	for s.Scan() {
		line++
		text := strings.TrimSpace(s.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		if strings.HasPrefix(text, "[") {
			if !strings.HasSuffix(text, "]") {
				return out, fmt.Errorf("config line %d: bad section", line)
			}
			section = strings.TrimSpace(text[1 : len(text)-1])
			if section == "ap-frames" || section == "sta-frames" {
				if _, exists := out.frames[section]; !exists {
					out.frames[section] = []string{}
				}
			}
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return out, fmt.Errorf("config line %d: expected key=value", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch section {
		case "fuzzing_option":
			out.values[key] = value
		case "interfaces":
			if _, e = strconv.Atoi(value); e != nil {
				return out, fmt.Errorf("config line %d: channel", line)
			}
			out.interfaces = append(out.interfaces, key)
			out.channels = append(out.channels, value)
		case "ap-frames", "sta-frames":
			if value == "1" {
				out.frames[section] = append(out.frames[section], key)
			} else if value != "0" {
				return out, fmt.Errorf("config line %d: frame flag must be 0/1", line)
			}
		case "ies-status", "ext-ies-status":
			id, err := strconv.ParseUint(key, 10, 8)
			if err != nil || value != "0" && value != "1" {
				return out, fmt.Errorf("config line %d: IE flag must be uint8=0/1", line)
			}
			if section == "ies-status" {
				out.disabled[byte(id)] = value == "0"
			} else {
				out.disabledExtensions[byte(id)] = value == "0"
			}
		case "mitm":
			if value != "" {
				out.values["mitm."+key] = value
			}
		default:
			return out, fmt.Errorf("unsupported config section %q; use --ie for explicit information elements", section)
		}
	}
	return out, s.Err()
}

// configArgs translates supported INI options to the same validated CLI path.
func configArgs(c config) []string {
	var out []string
	mapping := map[string]string{"fuzz_mode": "role", "bssid": "bssid", "target_mac": "destination", "source_mac": "source", "ssid": "ssid", "auth_type": "auth", "seed": "seed", "target_ip": "target-ip", "test_type": "T", "log_file": "log"}
	keys := []string{"fuzz_mode", "bssid", "target_mac", "source_mac", "ssid", "auth_type", "seed", "target_ip", "test_type", "log_file"}
	for _, key := range keys {
		if v, present := c.values[key]; present {
			out = append(out, "--"+mapping[key], v)
		}
	}
	section := "ap-frames"
	if c.values["fuzz_mode"] == "sta" {
		section = "sta-frames"
	}
	if len(c.frames[section]) > 0 && c.values["fuzz_mode"] != "p2p" && c.values["fuzz_mode"] != "awdl" && c.values["fuzz_mode"] != "mesh" && (c.values["test_type"] == "2" || c.values["test_type"] == "3" || c.values["test_type"] == "") {
		out = append(out, "--frame", strings.Join(c.frames[section], ","))
	}
	if len(c.interfaces) > 0 {
		out = append(out, "--interface", strings.Join(c.interfaces, ","), "--channel", strings.Join(c.channels, ","))
	}
	return out
}
