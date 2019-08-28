package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/psanford/wormhole-william/random"
	"github.com/psanford/wormhole-william/rendezvous"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

// client or just send() and recv() methods?

type Client struct {
	// AppID is the identity string of the client sent to the rendezvous server.
	// Two clients can only communicate if they have the same AppID.
	// The AppID should be a domain name + path to make it globally unique.
	// If empty, WormholeCLIAppID will be used.
	AppID string
	// RendezvousURL is the url of the Rendezvous server. If empty,
	// DefaultRendezvousURL will be used.
	RendezvousURL string

	// PassPhraseComponentLength is the number of words to use
	// when generating a passprase. Any value less than 2 will
	// default to 2.
	PassPhraseComponentLength int
}

var WormholeCLIAppID = "lothar.com/wormhole/text-or-file-xfer"
var DefaultRendezvousURL = "ws://localhost:4000/v1"

// var DefaultRendezvousURL = "ws://relay.magic-wormhole.io:4000/v1"

func NewClient() *Client {
	return &Client{}
}

func (c *Client) url() string {
	if c.RendezvousURL != "" {
		return c.RendezvousURL
	}
	return DefaultRendezvousURL
}

func (c *Client) appID() string {
	if c.AppID != "" {
		return c.AppID
	}
	return WormholeCLIAppID
}

func (c *Client) wordCount() int {
	if c.PassPhraseComponentLength > 1 {
		return c.PassPhraseComponentLength
	} else {
		return 2
	}
}

type SendResult struct {
	OK    bool
	Error error
}

var errDecryptFailed = errors.New("Decrypt message failed")

func openAndUnmarshal(v interface{}, mb rendezvous.MailboxEvent, sharedKey []byte) error {
	keySlice := derivePhaseKey(string(sharedKey), mb.Side, mb.Phase)
	nonceAndSealedMsg, err := hex.DecodeString(mb.Body)
	if err != nil {
		return err
	}

	nonce, sealedMsg := splitNonce(nonceAndSealedMsg)

	var openKey [32]byte
	copy(openKey[:], keySlice)

	out, ok := secretbox.Open(nil, sealedMsg, &nonce, &openKey)
	if !ok {
		return errDecryptFailed
	}

	return json.Unmarshal(out, v)
}

func sendEncryptedMessage(ctx context.Context, rc *rendezvous.Client, msg, sharedKey []byte, sideID, phase string) error {
	var sealKey [32]byte
	nonce := random.Nonce()

	msgKey := derivePhaseKey(string(sharedKey), sideID, phase)
	copy(sealKey[:], msgKey)

	sealedMsg := secretbox.Seal(nil, msg, &nonce, &sealKey)
	nonceAndSealedMsg := append(nonce[:], sealedMsg...)
	hexNonceAndSealedMsg := hex.EncodeToString(nonceAndSealedMsg)

	return rc.AddMessage(ctx, phase, hexNonceAndSealedMsg)
}

func jsonHexMarshal(msg interface{}) string {
	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(jsonMsg)
}

func jsonHexUnmarshal(hexStr string, msg interface{}) error {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, msg)
}

const secreboxKeySize = 32

func derivePhaseKey(key, side, phase string) []byte {
	sideSha := sha256.Sum256([]byte(side))
	phaseSha := sha256.Sum256([]byte(phase))
	purpose := "wormhole:phase:" + string(sideSha[:]) + string(phaseSha[:])

	r := hkdf.New(sha256.New, []byte(key), nil, []byte(purpose))
	out := make([]byte, secreboxKeySize)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}
	return out
}

func deriveTransitKey(key, appID string) []byte {
	purpose := appID + "/transit-key"

	r := hkdf.New(sha256.New, []byte(key), nil, []byte(purpose))
	out := make([]byte, secreboxKeySize)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}
	return out
}

type pakeMsg struct {
	Body string `json:"pake_v1"`
}

type offerMsg struct {
	Message   *string         `json:"message"`
	Directory *offerDirectory `json:"directory"`
	File      *offerFile      `json:"file"`
}

type offerDirectory struct {
	Dirname  string `json:"dirname"`
	Mode     string `json:"mode"`
	NumBytes int64  `json:"numbytes"`
	NumFiles int64  `json:"numfiles"`
	ZipSize  int64  `json:"zipsize"`
}

type offerFile struct {
	FileName string `json:"filename"`
	FileSize int64  `json:"filesize"`
}

type genericMessage struct {
	Offer       *offerMsg       `json:"offer"`
	Answer      *answerMsg      `json:"answer"`
	Transit     *transitMsg     `json:"transit"`
	AppVersions *appVersionsMsg `json:"app_versions"`
}

type appVersionsMsg struct {
}

type answerMsg struct {
	MessageAck string `json:"message_ack"`
}

func splitNonce(sealedMsg []byte) (nonce [24]byte, msg []byte) {
	copy(nonce[:], sealedMsg[:24])
	return nonce, sealedMsg[24:]
}

type transitAbility struct {
	Type string `json:"type"`
}

type transitHintsV1 struct {
	Hostname string               `json:"hostname"`
	Port     int64                `json:"port"`
	Priority int64                `json:"priority"`
	Type     string               `json:"type"`
	Hints    []transitHintsV1Hint `json:"hints"`
}

type transitHintsV1Hint struct {
	Hostname string `json:"hostname"`
	Port     int64  `json:"port"`
	Priority int64  `json:"priority"`
	Type     string `json:"type"`
}

type transitMsg struct {
	AbilitiesV1 []transitAbility `json:"abilities-v1"`
	HintsV1     []transitHintsV1 `json:"hints-v1"`
}
