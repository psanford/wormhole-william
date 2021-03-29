package internal

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SimpleURL holds protocol, host, port, and path information parsed from a URL.
type SimpleURL struct {
	Proto string
	Host  string
	Port  int
	Path  string
}

var (
	// MalformedProtoErr is used if forward slashes were absent in a
	// http-based protocol url, or present in a tcp url.
	MalformedProtoErr = errors.New("invalid URL for specified protocol (missing or unnecessary \"//\")")
	// InvalidPortErr is used when we were unable to convert the specified port to an integer.
	InvalidPortErr = errors.New("missing port")
)

// NewSimpleURL parses a url string of the format <proto>:[//]<host>:<port>,
// where <proto> defaults to "tcp" if unspecified. An empty url string returns
// the zero value of SimpleURL. Forward slashes are required for http-based URLs
// (i.e. ws & wss).
func NewSimpleURL(url string) (SimpleURL, error) {
	urlParts := strings.Split(url, ":")

	var proto, host string
	var port int

	switch len(urlParts) {
	case 2:
		// NB: unshift empty string int urlParts if no protocol in url.
		urlParts = append([]string{""}, urlParts...)
	case 3:
	default:
		return SimpleURL{
			Proto: "tcp",
			Host:  "",
			Port:  0,
		}, nil
	}

	// NB: defaults to tcp
	proto = urlParts[0]
	if proto == "" {
		proto = "tcp"
	}

	host = urlParts[1]
	portPath := strings.SplitN(urlParts[2], "/", 2)
	path := ""
	if len(portPath) == 2 {
		if portPath[1] != "" {
			path = "/" + portPath[1]
		} else {
			path = "/"
		}
	}
	port, err := strconv.Atoi(portPath[0])
	if err != nil {
		return SimpleURL{}, InvalidPortErr
	}

	switch urlParts[0] {
	case "http", "https", "ws", "wss":
		// http-based URL protocols include "//" so we need to remove it.
		// (see RFC2616 3.2.2 http URL)
		if host[:2] != "//" {
			return SimpleURL{}, MalformedProtoErr
		}
		host = host[2:]
	default:
		if host[:2] == "//" {
			return SimpleURL{}, MalformedProtoErr
		}
	}

	return SimpleURL{
		Proto: proto,
		Host:  host,
		Port:  port,
		Path:  path,
	}, nil
}

// MustNewSimpleURL parses a url string of the format <proto>:[//]<host>:<port>,
// panics if `NewSimpleURL` returns an error (see NewSimpleURL).
func MustNewSimpleURL(input string) SimpleURL {
	url, err := NewSimpleURL(input)
	if err != nil {
		panic(err)
	}
	return url
}

// String joins the url parts with a ":" and appends "//" to the protocol colon if it is http-based.
func (url SimpleURL) String() string {
	// TODO: that url path has to come from the other side via transit message.
	// At the moment, it is hard coded here as "/".
	// The RelayHint messages carry only host, port, type and priority, so this
	// is something that needs to be modified at the message level. Perhaps create
	// a new version of the Hints message called HintsV2?
	slashes := ""
	switch url.Proto {
	case "http", "https", "ws", "wss":
		// TODO: The hardcoding of the URL should be removed once there is
		// a way to represent it in the Hint messages. At the moment, there
		// is no way to do that and hence this hardcoding.
		slashes = "//"
	}
	path := url.Path
	if url.Path != "" {
		path = url.Path
	}
	return fmt.Sprintf("%s:%s%s:%d%s", url.Proto, slashes, url.Host, url.Port, path)
}

func (url SimpleURL) Addr() string {
	return net.JoinHostPort(url.Host, strconv.Itoa(url.Port))
}
