package output

import (
	"encoding/json"
	"fmt"

	"github.com/sharmajidotdev/netra/pkg/types"
)

// WriteJSON prints findings as JSON
func WriteJSON(res *types.Result) {
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}
