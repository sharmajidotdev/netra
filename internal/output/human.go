package output

import (
	"fmt"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// WriteHuman prints findings in a human-readable format
func WriteHuman(res *types.Result) {
	fmt.Println("Findings:")
	for _, f := range res.Findings {
		fmt.Printf(" - %s:%d %s\n", f.File, f.Line, f.SecretType)
	}
}
