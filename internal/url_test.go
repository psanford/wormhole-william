package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSimpleURL_protocols(t *testing.T) {
	testCases := []struct {
		name         string
		inputURL     string
		expectedAddr string
		expectedURL  SimpleURL
	}{
		{
			name:         "TCP with host and port",
			inputURL:     "tcp:1.1.1.1:2222",
			expectedAddr: "1.1.1.1:2222",
			expectedURL: SimpleURL{
				Proto: "tcp",
				Host:  "1.1.1.1",
				Port:  2222,
			},
		},
		{
			name:         "WS with host and port",
			inputURL:     "ws://1.1.1.1:2222",
			expectedAddr: "1.1.1.1:2222",
			expectedURL: SimpleURL{
				Proto: "ws",
				Host:  "1.1.1.1",
				Port:  2222,
			},
		},
		{
			name:         "WSS with host and port",
			inputURL:     "wss://1.1.1.1:2222",
			expectedAddr: "1.1.1.1:2222",
			expectedURL: SimpleURL{
				Proto: "wss",
				Host:  "1.1.1.1",
				Port:  2222,
			},
		},
		{
			name:         "WS with path",
			inputURL:     "ws://1.1.1.1:2222/some/path",
			expectedAddr: "1.1.1.1:2222",
			expectedURL: SimpleURL{
				Proto: "ws",
				Host:  "1.1.1.1",
				Port:  2222,
			},
		},
		{
			name:         "WS with trailing slash",
			inputURL:     "ws://1.1.1.1:2222/",
			expectedAddr: "1.1.1.1:2222",
			expectedURL: SimpleURL{
				Proto: "ws",
				Host:  "1.1.1.1",
				Port:  2222,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected := tc.expectedURL
			actual, err := NewSimpleURL(tc.inputURL)
			require.NoError(t, err)

			// TODO: make separate test
			_ = MustNewSimpleURL(tc.inputURL)

			require.Equal(t, tc.inputURL, actual.String())
			require.Equal(t, tc.expectedAddr, actual.Addr())
			require.Equal(t, expected.Proto, actual.Proto)
			require.Equal(t, expected.Host, actual.Host)
			require.Equal(t, expected.Port, actual.Port)
		})
	}
}

func TestNewSimpleURL_default_proto_tcp(t *testing.T) {
	inputURL := "1.1.1.1:2222"
	expected := SimpleURL{
		Proto: "tcp",
		Host:  "1.1.1.1",
		Port:  2222,
	}
	actual, err := NewSimpleURL(inputURL)
	require.NoError(t, err)

	// TODO: make separate test?
	_ = MustNewSimpleURL(inputURL)

	require.Equal(t, "tcp:1.1.1.1:2222", actual.String())
	require.Equal(t, "1.1.1.1:2222", actual.Addr())
	require.Equal(t, expected.Proto, actual.Proto)
	require.Equal(t, expected.Host, actual.Host)
	require.Equal(t, expected.Port, actual.Port)
}

func TestNewSimpleURL_empty_string(t *testing.T) {
	expectedAddr := ":0"
	expectedURL := SimpleURL{
		Proto: "tcp",
		Host:  "",
		Port:  0,
	}
	actual, err := NewSimpleURL("")
	require.NoError(t, err)

	// TODO: make separate test?
	_ = MustNewSimpleURL("")

	require.Equal(t, "tcp::0", actual.String())
	require.Equal(t, expectedAddr, actual.Addr())
	require.Equal(t, expectedURL.Proto, actual.Proto)
	require.Equal(t, expectedURL.Host, actual.Host)
	require.Equal(t, expectedURL.Port, actual.Port)
}

func TestNewSimpleURL_error(t *testing.T) {
	testCases := []struct {
		name        string
		inputURL    string
		expectedErr error
	}{
		{
			name:        "WS without `//`",
			inputURL:    "ws:1.1.1.1:2222",
			expectedErr: MalformedProtoErr,
		},
		{
			name:        "WSS without `//`",
			inputURL:    "wss:1.1.1.1:2222",
			expectedErr: MalformedProtoErr,
		},
		{
			name:        "TCP with `//`",
			inputURL:    "tcp://1.1.1.1:2222",
			expectedErr: MalformedProtoErr,
		},
		{
			name:        "missing protocol with `//`",
			inputURL:    "//1.1.1.1:2222",
			expectedErr: MalformedProtoErr,
		},
		{
			name:        "tcp with missing port",
			inputURL:    "tcp:1.1.1.1",
			expectedErr: InvalidPortErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NewSimpleURL(tc.inputURL)
			if assert.Error(t, err) {
				require.Equal(t, tc.expectedErr, err)
			}
			require.Zero(t, actual)
		})
	}
}
