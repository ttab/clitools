package clitools

import (
	"io"
	"strings"
	"testing"
)

func TestAskYesNo(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		def     bool
		want    bool
		wantErr bool
	}{
		{name: "empty takes the default yes", input: "\n", def: true, want: true},
		{name: "empty takes the default no", input: "\n", def: false, want: false},
		{name: "yes", input: "yes\n", want: true},
		{name: "no", input: "N\n", def: true, want: false},
		{name: "asks again after nonsense", input: "maybe\ny\n", want: true},
		{name: "answer without newline", input: "y", want: true},
		{name: "end of input", input: "", def: true, wantErr: true},
		{name: "nonsense at end of input", input: "maybe", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := askYesNo(strings.NewReader(tt.input), io.Discard, "Continue?", tt.def)

			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("got %v, want an error", got)
			case !tt.wantErr && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case !tt.wantErr && got != tt.want:
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
