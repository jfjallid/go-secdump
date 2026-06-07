package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// safeCall runs fn and converts any panic into a test failure with the
// crashing input attached. Fuzz targets call this to report the input
// alongside the panic message instead of the bare panic trace.
func safeCall(t *testing.T, name string, data []byte, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked on %d-byte input %x: %v", name, len(data), data, r)
		}
	}()
	fn()
}

// FuzzLSASecretUnmarshal explores lsaSecret.unmarshal, which currently
// slices data[:4], data[4:20], data[20:24], data[24:28], data[28:] with
// no bounds check. Inputs shorter than 28 bytes will panic — that's a
// real bug worth surfacing.
func FuzzLSASecretUnmarshal(f *testing.F) {
	// Seed: a 32-byte valid layout.
	valid := make([]byte, 0, 32)
	valid = binary.LittleEndian.AppendUint32(valid, 1)
	valid = append(valid, bytes.Repeat([]byte{0xAB}, 16)...) // EncKeyId
	valid = binary.LittleEndian.AppendUint32(valid, 2)       // EncAlgorithm
	valid = binary.LittleEndian.AppendUint32(valid, 3)       // Flags
	valid = append(valid, 0xDE, 0xAD, 0xBE, 0xEF)            // EncryptedData
	f.Add(valid)
	f.Add([]byte{})         // explicit empty (known panic candidate)
	f.Add([]byte{0x00, 0x01}) // truncated header
	f.Add(make([]byte, 28))   // minimum non-panicking length
	f.Add(make([]byte, 4096)) // large
	f.Fuzz(func(t *testing.T, data []byte) {
		safeCall(t, "lsaSecret.unmarshal", data, func() {
			s := &lsaSecret{}
			s.unmarshal(data)
		})
	})
}

func FuzzLSASecretBlobUnmarshal(f *testing.F) {
	// Seed: a valid blob with Length=4.
	valid := make([]byte, 0, 24)
	valid = binary.LittleEndian.AppendUint32(valid, 4)
	valid = append(valid, bytes.Repeat([]byte{0x77}, 12)...)
	valid = append(valid, 0x01, 0x02, 0x03, 0x04)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, 15))   // less than the 16-byte header
	f.Add(make([]byte, 1024)) // Length field unbounded by buffer size
	f.Fuzz(func(t *testing.T, data []byte) {
		safeCall(t, "lsaSecretBlob.unmarshal", data, func() {
			b := &lsaSecretBlob{}
			b.unmarshal(data)
		})
	})
}

func FuzzDPAPISystemUnmarshal(f *testing.F) {
	valid := make([]byte, 0, 44)
	valid = binary.LittleEndian.AppendUint32(valid, 2)
	valid = append(valid, bytes.Repeat([]byte{0xa1}, 20)...)
	valid = append(valid, bytes.Repeat([]byte{0xb2}, 20)...)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, 43)) // one short of the 44-byte fixed layout
	f.Fuzz(func(t *testing.T, data []byte) {
		safeCall(t, "dpapiSystem.unmarshal", data, func() {
			d := &dpapiSystem{}
			d.unmarshal(data)
		})
	})
}

func FuzzDomainAccountFUnmarshal(f *testing.F) {
	// Seed: 104-byte minimum (which is the length check the function
	// already enforces).
	valid := make([]byte, 104)
	binary.LittleEndian.PutUint16(valid[0:], 3)
	f.Add(valid)
	// Variants with trailing payload of various lengths.
	withPayload := append(append([]byte{}, valid...), bytes.Repeat([]byte{0x55}, 64)...)
	f.Add(withPayload)
	f.Add([]byte{})
	f.Add(make([]byte, 103))
	f.Fuzz(func(t *testing.T, data []byte) {
		safeCall(t, "domain_account_f.unmarshal", data, func() {
			a := &domain_account_f{}
			_ = a.unmarshal(data)
		})
	})
}

func FuzzNLRecordUnmarshal(f *testing.F) {
	// Seed: 96-byte minimum.
	valid := make([]byte, 96)
	binary.LittleEndian.PutUint16(valid[0:], 14)
	binary.LittleEndian.PutUint16(valid[2:], 12)
	binary.LittleEndian.PutUint32(valid[16:], 500)
	binary.LittleEndian.PutUint32(valid[48:], 1)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, 95))
	f.Add(append(append([]byte{}, valid...), bytes.Repeat([]byte{0xff}, 256)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		safeCall(t, "nl_record.unmarshal", data, func() {
			r := &nl_record{}
			_ = r.unmarshal(data)
		})
	})
}
