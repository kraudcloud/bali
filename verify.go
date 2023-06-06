package main

import (
	"compress/gzip"
	"crypto/sha512"
	"fmt"
	ik "github.com/devguardio/identity/go"
	"io"
)

func Verify(ii io.ReadSeeker, identity string) error {

	id, err := ik.IdentityFromString(identity)
	if err != nil {
		return err
	}

	// peek to check if its gzip
	peek := make([]byte, 2)
	ii.Read(peek)
	ii.Seek(0, 0)

	var ir io.Reader = ii

	if peek[0] == 0x1f && peek[1] == 0x8b {
		ir, err = gzip.NewReader(ii)
		if err != nil {
			return err
		}
	}

	hasher := sha512.New()

	// read to end but keep last 80 bytes
	var last80 [80]byte
	var buf [4096]byte
	var first = true
	for {
		n, err := ir.Read(buf[:])
		if err != nil {
			if err != io.EOF {
				return err
			}
		}

		if n == 0 {
			break
		} else if n == 80 {
			if !first {
				hasher.Write(last80[:])
			}
			copy(last80[:], buf[:n])
			break
		} else if n >= 80 {
			if !first {
				hasher.Write(last80[:])
			}
			hasher.Write(buf[:n-80])
			copy(last80[:], buf[n-80:n])
		} else {
			// if the current read is less than 80 bytes, the rest is still in last80
			if !first {
				hasher.Write(last80[:n])
			}
			copy(last80[:len(last80)-n], last80[n:])
			copy(last80[len(last80)-n:], buf[:n])
			break
		}

		first = false
	}

	if last80[8] != 'i' || last80[9] != 'k' || last80[10] != 's' || last80[11] != 'i' || last80[12] != 'g' {
		return fmt.Errorf("no signature found")
	}

	var sig ik.Signature
	copy(sig[:], last80[16:])

	err = sig.VerifyPrehashed("bali", hasher.Sum(nil), id)
	if err != nil {
		return err
	}

	return nil
}
