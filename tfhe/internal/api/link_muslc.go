//go:build linux && muslc

package api

// #cgo LDFLAGS: -Wl,-rpath,${SRCDIR} -L${SRCDIR} -ltfhe_wrapper_muslc
import "C"
