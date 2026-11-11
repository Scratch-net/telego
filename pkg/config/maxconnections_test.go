package config

import (
	"testing"
)

func withFileDescriptorLimit(t *testing.T, soft uint64, ok bool) {
	t.Helper()
	previous := fileDescriptorSoftLimit
	fileDescriptorSoftLimit = func() (uint64, bool) { return soft, ok }
	t.Cleanup(func() { fileDescriptorSoftLimit = previous })
}

func TestGlobalMaxConnections(t *testing.T) {
	const base = "secrets.test = \"0123456789abcdef0123456789abcdef\"\ntls-fronting.mask-host = \"example.com\"\n"
	tests := []struct {
		name    string
		extra   string
		soft    uint64
		ok      bool
		want    int
		wantErr bool
	}{
		{"direct auto", "middle-end.enabled = false\n", 65536, true, (65536 - 256) / 2, false},
		{"direct small limit", "middle-end.enabled = false\n", 1024, true, (1024 - 256) / 2, false},
		{"direct tiny limit", "middle-end.enabled = false\n", 64, true, 16, false},
		{"direct unknown limit", "middle-end.enabled = false\n", 0, false, 0, false},
		{"direct explicit", "middle-end.enabled = false\ngeneral.max-connections = 500\n", 65536, true, 500, false},
		{"middle-end below auto", "", 1 << 20, true, middleEndDefaultMaxConnections, false},
		{"auto below middle-end", "", 4096, true, (4096 - 256) / 2, false},
		{"explicit below middle-end", "general.max-connections = 300\n", 1 << 20, true, 300, false},
		{"negative", "general.max-connections = -1\n", 65536, true, 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withFileDescriptorLimit(t, test.soft, test.ok)
			cfg, err := Load(writeConfigTestFile(t, base+test.extra))
			if err != nil && !test.wantErr {
				t.Fatal(err)
			}
			if err == nil {
				_, err = cfg.ToGProxyConfig()
			}
			if test.wantErr {
				if err == nil {
					t.Fatal("negative general.max-connections accepted")
				}
				return
			}
			runtime, err := cfg.ToGProxyConfig()
			if err != nil {
				t.Fatal(err)
			}
			if runtime.MaxConnections != test.want {
				t.Fatalf("MaxConnections = %d, want %d", runtime.MaxConnections, test.want)
			}
		})
	}
}
