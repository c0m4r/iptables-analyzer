package services

import (
	"os"
	"path/filepath"
	"testing"
	"unicode"
)

func FuzzParseSSData(f *testing.F) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "services.txt"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(data))
	f.Add("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 1 [::]:22 [::]:* users:((\"\x1b[2Jx\",pid=1,fd=3))\n")
	f.Fuzz(func(t *testing.T, data string) {
		services, _ := ParseSSData(data)
		for _, svc := range services {
			if svc.Port < 1 || svc.Port > 65535 {
				t.Fatalf("invalid port accepted: %+v", svc)
			}
			for _, r := range svc.Process + svc.Address {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					t.Fatalf("control character in service %+v", svc)
				}
			}
		}
	})
}
