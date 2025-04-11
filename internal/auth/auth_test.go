package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name			string
		authHeader		string
		expectedKey		string
		expectingErr	bool
		expectedErr		error
	}{
		{
			name: "no auth header",
			authHeader: "",
			expectedKey: "",
			expectingErr: true,
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			authHeader: "Bearer abcdef123",
			expectedKey: "",
			expectingErr: true,
		},
		{
			name: "malformed header - only one part",
			authHeader: "ApiKeyOnly",
			expectedKey: "",
			expectingErr: true,
		},
		{
			name: "valid header",
			authHeader: "ApiKey my-secret-key",
			expectedKey: "my-secret-key",
			expectingErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			key, err := GetAPIKey(headers)

			if tc.expectingErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				if tc.expectedErr != nil && err != tc.expectedErr {
					t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error but got %v", err)
				}
				if key != tc.expectedKey {
					t.Errorf("expected key %q, got %q", tc.expectedKey, key)
				}
			}
		})
	}
}