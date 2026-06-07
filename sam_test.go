package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestLSASecret_Unmarshal(t *testing.T) {
	// Layout: version(4) | EncKeyId(16) | EncAlgorithm(4) | Flags(4) | EncryptedData(...)
	buf := make([]byte, 0, 64)
	buf = binary.LittleEndian.AppendUint32(buf, 0x12345678)
	encKeyId := []byte("KEY-ID-16-BYTES!")
	if len(encKeyId) != 16 {
		t.Fatalf("test setup: encKeyId must be 16 bytes")
	}
	buf = append(buf, encKeyId...)
	buf = binary.LittleEndian.AppendUint32(buf, 9)
	buf = binary.LittleEndian.AppendUint32(buf, 0xdeadbeef)
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	buf = append(buf, payload...)

	s := &lsaSecret{}
	s.unmarshal(buf)

	if s.Version != 0x12345678 {
		t.Errorf("Version: got %#x, want 0x12345678", s.Version)
	}
	if s.EncKeyId != string(encKeyId) {
		t.Errorf("EncKeyId: got %q, want %q", s.EncKeyId, encKeyId)
	}
	if s.EncAlgorithm != 9 {
		t.Errorf("EncAlgorithm: got %d, want 9", s.EncAlgorithm)
	}
	if s.Flags != 0xdeadbeef {
		t.Errorf("Flags: got %#x, want 0xdeadbeef", s.Flags)
	}
	if !bytes.Equal(s.EncryptedData, payload) {
		t.Errorf("EncryptedData: got %x, want %x", s.EncryptedData, payload)
	}
}

func TestLSASecretBlob_Unmarshal(t *testing.T) {
	// Layout: Length(4) | Unknown(12) | Secret(Length bytes)
	secret := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	buf := make([]byte, 0, 16+len(secret)+4)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(secret)))
	buf = append(buf, bytes.Repeat([]byte{0x77}, 12)...)
	buf = append(buf, secret...)
	// Extra trailing bytes should be ignored.
	buf = append(buf, 0x99, 0x99, 0x99)

	b := &lsaSecretBlob{}
	b.unmarshal(buf)

	if b.Length != uint32(len(secret)) {
		t.Errorf("Length: got %d, want %d", b.Length, len(secret))
	}
	for _, u := range b.Unknown {
		if u != 0x77 {
			t.Errorf("Unknown byte: got %#x, want 0x77", u)
		}
	}
	if !bytes.Equal(b.Secret, secret) {
		t.Errorf("Secret: got %x, want %x", b.Secret, secret)
	}
}

func TestDPAPISystem_Unmarshal(t *testing.T) {
	buf := make([]byte, 0, 44)
	buf = binary.LittleEndian.AppendUint32(buf, 2)
	machine := bytes.Repeat([]byte{0xa1}, 20)
	user := bytes.Repeat([]byte{0xb2}, 20)
	buf = append(buf, machine...)
	buf = append(buf, user...)

	d := &dpapiSystem{}
	d.unmarshal(buf)
	if d.Version != 2 {
		t.Errorf("Version: got %d, want 2", d.Version)
	}
	if !bytes.Equal(d.MachineKey[:], machine) {
		t.Errorf("MachineKey: got %x, want %x", d.MachineKey[:], machine)
	}
	if !bytes.Equal(d.UserKey[:], user) {
		t.Errorf("UserKey: got %x, want %x", d.UserKey[:], user)
	}
}

func TestDomainAccountF_Unmarshal(t *testing.T) {
	// Build the 104-byte fixed header. Pick distinguishable values for the
	// fields we read so a wrong offset in the unmarshaler is caught.
	buf := make([]byte, 104)
	binary.LittleEndian.PutUint16(buf[0:], 3) // Revision (AES)
	binary.LittleEndian.PutUint64(buf[8:], 0x1111111111111111)   // CreationTime
	binary.LittleEndian.PutUint64(buf[16:], 0x2222222222222222)  // DomainModifiedAccount
	binary.LittleEndian.PutUint64(buf[24:], 0x3333333333333333)  // MaxPasswordAge
	binary.LittleEndian.PutUint64(buf[32:], 0x4444444444444444)  // MinPasswordAge
	binary.LittleEndian.PutUint64(buf[40:], 0x5555555555555555)  // ForceLogoff
	binary.LittleEndian.PutUint64(buf[48:], 0x6666666666666666)  // LockoutDuration
	binary.LittleEndian.PutUint64(buf[56:], 0x7777777777777777)  // LockoutObservationWindow
	binary.LittleEndian.PutUint64(buf[64:], 0x8888888888888888)  // ModifiedCountAtLastPromotion
	binary.LittleEndian.PutUint32(buf[72:], 0x09090909)          // NextRid
	binary.LittleEndian.PutUint32(buf[76:], 0x0a0a0a0a)          // PasswordProperties
	binary.LittleEndian.PutUint16(buf[80:], 0x0b0b)              // MinPasswordLength
	binary.LittleEndian.PutUint16(buf[82:], 0x0c0c)              // PasswordHistoryLength
	binary.LittleEndian.PutUint16(buf[84:], 0x0d0d)              // LockoutThreshold
	binary.LittleEndian.PutUint32(buf[88:], 0x0e0e0e0e)          // ServerState
	binary.LittleEndian.PutUint32(buf[92:], 0x0f0f0f0f)          // ServerRole
	binary.LittleEndian.PutUint32(buf[96:], 0x10101010)          // UasCompatibilityRequired
	trailing := []byte{0xfe, 0xed, 0xfa, 0xce}
	buf = append(buf, trailing...)

	f := &domain_account_f{}
	if err := f.unmarshal(buf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.Revision != 3 {
		t.Errorf("Revision: got %d, want 3", f.Revision)
	}
	if f.NextRid != 0x09090909 {
		t.Errorf("NextRid: got %#x, want 0x09090909", f.NextRid)
	}
	if f.LockoutThreshold != 0x0d0d {
		t.Errorf("LockoutThreshold: got %#x, want 0x0d0d", f.LockoutThreshold)
	}
	if !bytes.Equal(f.Data, trailing) {
		t.Errorf("Data: got %x, want %x", f.Data, trailing)
	}
}

func TestDomainAccountF_Unmarshal_TruncatedRejected(t *testing.T) {
	f := &domain_account_f{}
	for _, sz := range []int{0, 1, 50, 103} {
		err := f.unmarshal(make([]byte, sz))
		if err == nil {
			t.Errorf("unmarshal(len=%d): want error, got nil", sz)
		}
	}
}

func TestNLRecord_Unmarshal(t *testing.T) {
	// 96 bytes fixed header.
	buf := make([]byte, 96)
	binary.LittleEndian.PutUint16(buf[0:], 14)  // UserLength
	binary.LittleEndian.PutUint16(buf[2:], 12)  // DomainNameLength
	binary.LittleEndian.PutUint16(buf[4:], 16)  // EffectiveNameLength
	binary.LittleEndian.PutUint16(buf[6:], 20)  // FullNameLength
	binary.LittleEndian.PutUint16(buf[8:], 0)   // LogonScriptName
	binary.LittleEndian.PutUint16(buf[10:], 0)  // ProfilePathLength
	binary.LittleEndian.PutUint16(buf[12:], 0)  // HomeDirectoryLength
	binary.LittleEndian.PutUint16(buf[14:], 0)  // HomeDirectoryDriveLength
	binary.LittleEndian.PutUint32(buf[16:], 500) // UserId
	binary.LittleEndian.PutUint32(buf[20:], 513) // PrimaryGroupId
	binary.LittleEndian.PutUint32(buf[24:], 2)   // GroupCount
	binary.LittleEndian.PutUint16(buf[28:], 8)   // logonDomainNameLength
	binary.LittleEndian.PutUint64(buf[32:], 0xfacefacefaceface) // LastWrite
	binary.LittleEndian.PutUint32(buf[40:], 1)   // Revision
	binary.LittleEndian.PutUint32(buf[48:], 1)   // Flags (encrypted)
	binary.LittleEndian.PutUint16(buf[60:], 24)  // DnsDomainNameLength
	iv := bytes.Repeat([]byte{0xa5}, 16)
	copy(buf[64:80], iv)
	ch := bytes.Repeat([]byte{0xc7}, 16)
	copy(buf[80:96], ch)
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x11, 0x22}
	buf = append(buf, payload...)

	r := &nl_record{}
	if err := r.unmarshal(buf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.UserLength != 14 {
		t.Errorf("UserLength: got %d, want 14", r.UserLength)
	}
	if r.UserId != 500 {
		t.Errorf("UserId: got %d, want 500", r.UserId)
	}
	if r.Flags != 1 {
		t.Errorf("Flags: got %d, want 1", r.Flags)
	}
	if r.DnsDomainNameLength != 24 {
		t.Errorf("DnsDomainNameLength: got %d, want 24", r.DnsDomainNameLength)
	}
	if !bytes.Equal(r.IV[:], iv) {
		t.Errorf("IV: got %x, want %x", r.IV[:], iv)
	}
	if !bytes.Equal(r.CH[:], ch) {
		t.Errorf("CH: got %x, want %x", r.CH[:], ch)
	}
	if !bytes.Equal(r.EncryptedData, payload) {
		t.Errorf("EncryptedData: got %x, want %x", r.EncryptedData, payload)
	}
}

func TestNLRecord_Unmarshal_TruncatedRejected(t *testing.T) {
	r := &nl_record{}
	for _, sz := range []int{0, 1, 50, 95} {
		err := r.unmarshal(make([]byte, sz))
		if err == nil {
			t.Errorf("unmarshal(len=%d): want error, got nil", sz)
		}
	}
}

func TestPad64(t *testing.T) {
	cases := []struct {
		in, out uint64
	}{
		{0, 0},
		{1, 4},
		{2, 4},
		{3, 4},
		{4, 4},
		{5, 8},
		{8, 8},
		{9, 12},
		{1023, 1024},
		{1024, 1024},
		{1025, 1028},
	}
	for _, c := range cases {
		if got := pad64(c.in); got != c.out {
			t.Errorf("pad64(%d) = %d, want %d", c.in, got, c.out)
		}
	}
}
