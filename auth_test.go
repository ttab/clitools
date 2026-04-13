package clitools

import "testing"

func TestEnsureWellKnownSuffix(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "realm URL without trailing slash",
			in:   "https://login.stage.tt.se/realms/elephant",
			want: "https://login.stage.tt.se/realms/elephant/.well-known/openid-configuration",
		},
		{
			name: "realm URL with trailing slash",
			in:   "https://login.stage.tt.se/realms/elephant/",
			want: "https://login.stage.tt.se/realms/elephant/.well-known/openid-configuration",
		},
		{
			name: "already has well-known suffix",
			in:   "https://login.stage.tt.se/realms/elephant/.well-known/openid-configuration",
			want: "https://login.stage.tt.se/realms/elephant/.well-known/openid-configuration",
		},
		{
			name: "bare host",
			in:   "https://login.stage.tt.se",
			want: "https://login.stage.tt.se/.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ensureWellKnownSuffix(tt.in)
			if got != tt.want {
				t.Errorf("ensureWellKnownSuffix(%q)\n got  %q\n want %q", tt.in, got, tt.want)
			}
		})
	}
}
