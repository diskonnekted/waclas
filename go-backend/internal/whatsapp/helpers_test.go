package whatsapp

import (
	"testing"

	"go.mau.fi/whatsmeow/types"
)

// Format nomor Indonesia yang lazim dipakai user harus berakhir di JID yang sama.
// Sebelumnya prefiks "0" dibuang begitu saja sehingga "0813..." menjadi
// "813...@s.whatsapp.net" dan pengiriman gagal dengan "no LID found".
func TestParseJIDNormalisasiNomor(t *testing.T) {
	cases := []struct {
		in  string
		jid string
	}{
		{"081328128315", "6281328128315@s.whatsapp.net"},
		{"6281328128315", "6281328128315@s.whatsapp.net"},
		{"+62 813-2812-8315", "6281328128315@s.whatsapp.net"},
		{"+6281328128315", "6281328128315@s.whatsapp.net"},
		{" 0813 2812 8315 ", "6281328128315@s.whatsapp.net"},
		{"(0813) 2812-8315", "6281328128315@s.whatsapp.net"},
		// Nomor luar negeri tanpa prefiks nasional tidak diubah.
		{"14155552671", "14155552671@s.whatsapp.net"},
		{"+1 415 555 2671", "14155552671@s.whatsapp.net"},
	}

	for _, c := range cases {
		got, err := parseJID(c.in)
		if err != nil {
			t.Fatalf("parseJID(%q) error: %v", c.in, err)
		}
		if got.String() != c.jid {
			t.Errorf("parseJID(%q) = %q, mau %q", c.in, got.String(), c.jid)
		}
	}
}

func TestParseJIDJIDUtuh(t *testing.T) {
	if got, err := parseJID("1234567890@s.whatsapp.net"); err != nil || got.User != "1234567890" {
		t.Fatalf("JID utuh harus diteruskan apa adanya, dapat %v / %v", got, err)
	}
	if got, err := parseJID("99887766554433@lid"); err != nil || got.Server != types.HiddenUserServer {
		t.Fatalf("LID harus dipertahankan server-nya, dapat %v / %v", got, err)
	}
}

func TestParseJIDKosong(t *testing.T) {
	if _, err := parseJID("  +  "); err == nil {
		t.Fatal("nomor tanpa digit harus menghasilkan error")
	}
}
