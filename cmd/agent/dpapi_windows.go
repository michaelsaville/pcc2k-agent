//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI wrapper for local-machine-scoped secrets. We use
// CRYPTPROTECT_LOCAL_MACHINE so the encrypted blob can be decrypted
// by any process running on the host (specifically: by the
// pcc2k-agent service running as LocalSystem). User-scoped DPAPI
// would be wrong — the install user usually isn't the run user.
//
// Trade-off: any local admin on the box can also decrypt. That's
// acceptable for the enrollment token because (a) local admin can
// already revoke the agent via SCM, and (b) the token only authorizes
// THIS host's connection, not impersonation of other hosts. Per
// HIPAA-READY §1 this is "encrypted at rest, not encrypted from
// administrators" — the design assumption matches.

const cryptProtectLocalMachine = 0x4

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		cbData: uint32(len(b)),
		pbData: &b[0],
	}
}

func (b *dataBlob) toBytes() []byte {
	out := make([]byte, b.cbData)
	if b.cbData == 0 {
		return out
	}
	src := unsafe.Slice(b.pbData, b.cbData)
	copy(out, src)
	return out
}

var (
	modCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
	modKernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree          = modKernel32.NewProc("LocalFree")
)

func dpapiProtect(plaintext []byte) ([]byte, error) {
	in := newBlob(plaintext)
	var out dataBlob

	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, // szDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		uintptr(cryptProtectLocalMachine),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.toBytes(), nil
}

func dpapiUnprotect(ciphertext []byte) ([]byte, error) {
	in := newBlob(ciphertext)
	var out dataBlob

	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(in)),
		0,
		0,
		0,
		0,
		uintptr(cryptProtectLocalMachine),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.toBytes(), nil
}
