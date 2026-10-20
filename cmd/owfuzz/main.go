// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"owfuzz/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if e := app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); e != nil {
		if errors.Is(e, context.Canceled) {
			return
		}
		fmt.Fprintln(os.Stderr, "owfuzz:", e)
		os.Exit(1)
	}
}
