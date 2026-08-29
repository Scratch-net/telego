package middleend

import "testing"

func FuzzParseProxyConfig(f *testing.F) {
	f.Add([]byte("default 1; proxy_for 1 192.0.2.1:443;"), byte(configIPv4))
	f.Add([]byte("# v6\nproxy_for -203 [2001:db8::1]:8888;"), byte(configIPv6))
	f.Add([]byte("proxy 192.0.2.1:443; proxy_for 1234 192.0.2.2:443;"), byte(configIPv4))
	f.Add([]byte("proxy_for 32768 host:0"), byte(0xff))

	f.Fuzz(func(t *testing.T, data []byte, familyByte byte) {
		family := configFamily(familyByte % 4)
		config, err := parseProxyConfig(data, family)
		if err != nil {
			return
		}
		if family != configIPv4 && family != configIPv6 {
			t.Fatalf("invalid family %d parsed successfully", family)
		}

		targets := 0
		if len(config.endpoints) > MaxProxyClusters {
			t.Fatalf("parsed cluster count = %d", len(config.endpoints))
		}
		for _, endpoints := range config.endpoints {
			for _, endpoint := range endpoints {
				address := endpoint.Addr()
				if !endpoint.IsValid() || endpoint.Port() == 0 || address.IsUnspecified() || address.Zone() != "" {
					t.Fatalf("unusable endpoint %s parsed successfully", endpoint)
				}
				if family == configIPv4 && !address.Is4() {
					t.Fatalf("non-IPv4 endpoint %s parsed as IPv4", endpoint)
				}
				if family == configIPv6 && (!address.Is6() || address.Is4In6()) {
					t.Fatalf("non-IPv6 endpoint %s parsed as IPv6", endpoint)
				}
			}
			targets += len(endpoints)
		}
		if targets == 0 || targets > MaxProxyTargets {
			t.Fatalf("parsed target count = %d", targets)
		}
	})
}
