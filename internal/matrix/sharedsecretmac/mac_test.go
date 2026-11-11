package sharedsecretmac

import "testing"

func TestCompute(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		nonce      string
		user       string
		credential string
		want       string
		admin      bool
	}{
		{
			name:       "admin role matches Synapse HMAC-SHA1 specification",
			key:        "example-secret-1",
			nonce:      "nonce-1",
			user:       "alice",
			credential: "example-pass-1",
			admin:      true,
			want:       "6deb7c4cd0b1e4cdef22ccfa3777e3dff62512ce",
		},
		{
			name:       "standard user uses notadmin suffix",
			key:        "example-secret-2",
			nonce:      "nonce-2",
			user:       "bob",
			credential: "example-pass-2",
			admin:      false,
			want:       "bf1ac54a35ded86974f1aefbcbbca9483be04b75",
		},
		{
			name:       "distinct inputs alter digest",
			key:        "example-secret-3",
			nonce:      "nonce-3",
			user:       "carol",
			credential: "example-pass-3",
			admin:      false,
			want:       "5295bd129039efcd742a4da4b5541d0b77ab4d3b",
		},
	}

	for _, tc := range tests {
		got := Compute(tc.key, tc.nonce, tc.user, tc.credential, tc.admin)
		if got != tc.want {
			t.Errorf("%s: Compute() = %q, want %q", tc.name, got, tc.want)
		}
	}
}
