// The h00ligan builder installs this dedicated main package over the pinned
// gopls command entrypoint. The resulting helper is embedded in the one-file
// h00ligan product and is never installed as a separate user command.
package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/tools/gopls/internal/cmd"
)

func main() {
	if err := cmd.H00SemanticProvider(context.Background()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Go semantic provider failed: %v\n", err)
		os.Exit(1)
	}
}
