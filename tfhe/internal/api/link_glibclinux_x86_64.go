//go:build linux && !muslc && amd64

package api

// #cgo LDFLAGS: -Wl,-rpath,${SRCDIR} -L${SRCDIR} -ltfhe_wrapper.x86_64
import "C"
