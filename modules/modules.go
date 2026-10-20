// SPDX-License-Identifier: GPL-3.0-or-later
// Package modules supplies built-in families. Add a Go file with an init provider;
// Go's build system discovers it without generated lists or compiler attributes.
package modules

import "owfuzz/protocol"

var providers []func() protocol.Family

func provide(f func() protocol.Family) { providers = append(providers, f) }
func RegisterAll(r *protocol.Registry) error {
	for _, f := range providers {
		if e := r.Register(f()); e != nil {
			return e
		}
	}
	return nil
}
func NewRegistry() (*protocol.Registry, error) { r := protocol.NewRegistry(); return r, RegisterAll(r) }
