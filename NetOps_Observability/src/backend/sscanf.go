package backend

import "fmt"

// fmtSscanfImpl is split into its own file so flows.go can keep its
// import block narrow and main.go's `fmt` import remains the only
// canonical site. Keeping the indirection lets us swap to a manual
// strconv parse later if we want to drop fmt from this package
// entirely.
func fmtSscanfImpl(s, format string, a ...any) (int, error) {
	return fmt.Sscanf(s, format, a...)
}
