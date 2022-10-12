package main

import (
	"testing"
)

func Test_nuclei(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
	}{
		{
			name: "scan vulnerably docker container",
			hosts: []string{
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
				"http://localhost",
			},
		},
	}

	for _, tt := range tests {
		var discoveredVulns int

		t.Run(tt.name, func(t *testing.T) {
			for i, host := range tt.hosts {
				got, err := nuclei(host)
				if err != nil {
					t.Errorf("nuclei() error = %v", err)
					return
				}

				if i == 0 {
					discoveredVulns = len(got)
				}

				t.Logf("scan %d: discovered %d vulnerabilites for target %s\n", i+1, len(got), host)
				if i != 0 && len(got) != discoveredVulns {
					t.Errorf("expected to discover %d vulnerabilites on subsequent scan with the same target, but discovered %d\n", discoveredVulns, len(got))
				}
			}
		})
	}
}
