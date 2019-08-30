// Package wormhole provides a magic wormhole client implementation.
package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"salsa.debian.org/vasudev/gospake2"
)

// A Client is wormhole client. Its zero value is a usable client.
type Client struct {
	// AppID is the identity string of the client sent to the rendezvous
	// server. Two clients can only communicate if they have the same
	// AppID. The AppID should be a domain name + path to make it
	// globally unique. If empty, WormholeCLIAppID will be used.
	AppID string
	// RendezvousURL is the url of the Rendezvous server. If empty,
	// DefaultRendezvousURL will be used.
	RendezvousURL string

	// TransitRelayAddress is the host:port address to offer
	// to use for file transfers where direct connections are unavailable.
	// If empty, DefaultTransitRelayAddress will be used.
	TransitRelayAddress string

	// PassPhraseComponentLength is the number of words to use
	// when generating a passprase. Any value less than 2 will
	// default to 2.
	PassPhraseComponentLength int
}

var (
	// WormholeCLIAppID is the AppID used by the python magic wormhole
	// client. In order to interoperate with that client you must use
	// the same AppID.
	WormholeCLIAppID = "lothar.com/wormhole/text-or-file-xfer"

	// DefaultRendezvousURL is the default Rendezvous server to use.
	DefaultRendezvousURL = "ws://relay.magic-wormhole.io:4000/v1"

	// DefaultTransitRelayAddress is the default transit server to ues.
	DefaultTransitRelayAddress = "transit.magic-wormhole.io:4001"
)

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

func (c *Client) relayAddr() string {
	if c.TransitRelayAddress != "" {
		return c.TransitRelayAddress
	}
	return DefaultTransitRelayAddress
}

func (c *Client) validateRelayAddr() error {
	if c.relayAddr() == "" {
		return nil
	}
	_, _, err := net.SplitHostPort(c.relayAddr())
	return err
}

// SendResult has information about whether or not a Send command was successful.
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
	nonce := crypto.RandNonce()

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

func deriveTransitKey(key []byte, appID string) []byte {
	purpose := appID + "/transit-key"

	r := hkdf.New(sha256.New, key, nil, []byte(purpose))
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
	Message   *string         `json:"message,omitempty"`
	Directory *offerDirectory `json:"directory,omitempty"`
	File      *offerFile      `json:"file,omitempty"`
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
	Offer       *offerMsg       `json:"offer,omitempty"`
	Answer      *answerMsg      `json:"answer,omitempty"`
	Transit     *transitMsg     `json:"transit,omitempty"`
	AppVersions *appVersionsMsg `json:"app_versions,omitempty"`
}

type appVersionsMsg struct {
}

type answerMsg struct {
	MessageAck string `json:"message_ack"`
	FileAck    string `json:"file_ack"`
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
	Port     int                  `json:"port"`
	Priority float64              `json:"priority"`
	Type     string               `json:"type"`
	Hints    []transitHintsV1Hint `json:"hints"`
}

type transitHintsV1Hint struct {
	Hostname string  `json:"hostname"`
	Port     int     `json:"port"`
	Priority float64 `json:"priority"`
	Type     string  `json:"type"`
}

type transitMsg struct {
	AbilitiesV1 []transitAbility `json:"abilities-v1"`
	HintsV1     []transitHintsV1 `json:"hints-v1"`
}

type msgCollector struct {
	sharedKey      []byte
	collectOffer   bool
	collectTransit bool
	collectAnswer  bool

	offer   *offerMsg
	answer  *answerMsg
	transit *transitMsg
}

func (c *msgCollector) collect(ch <-chan rendezvous.MailboxEvent) error {
	var pending int
	for _, collect := range []bool{c.collectOffer, c.collectTransit, c.collectAnswer} {
		if collect {
			pending++
		}
	}

	for pending > 0 {
		gotMsg, ok := <-ch
		if !ok {
			return errors.New("Channel closed before collecting all messages")
		}
		if gotMsg.Error != nil {
			return gotMsg.Error
		}

		if _, err := strconv.Atoi(gotMsg.Phase); err != nil {
			return fmt.Errorf("Got unexpected phase: %s", gotMsg.Phase)
		}

		var msg genericMessage
		err := openAndUnmarshal(&msg, gotMsg, c.sharedKey)
		if err != nil {
			return err
		}

		if msg.Offer != nil {
			if !c.collectOffer {
				return errors.New("Got offer message when wasn't expecting one")
			}
			if c.offer != nil {
				return errors.New("Got multiple offer messages")
			}

			c.offer = msg.Offer
		} else if msg.Transit != nil {
			if !c.collectTransit {
				return errors.New("Got transit message when wasn't expecting one")
			}
			if c.transit != nil {
				return errors.New("Got multiple transit messages")
			}

			c.transit = msg.Transit
		} else if msg.Answer != nil {
			if !c.collectAnswer {
				return errors.New("Got answer message when wasn't expecting one")
			}
			if c.answer != nil {
				return errors.New("Got multiple answer messages")
			}

			c.answer = msg.Answer
		} else {
			return fmt.Errorf("Got unexpected message")
		}

		pending--
	}

	return nil
}

type clientProtocol struct {
	sharedKey    []byte
	phaseCounter int
	ch           <-chan rendezvous.MailboxEvent
	rc           *rendezvous.Client
	spake        *gospake2.SPAKE2
	sideID       string
	appID        string
}

func newClientProtocol(ctx context.Context, rc *rendezvous.Client, sideID, appID string) *clientProtocol {
	recvChan := rc.MsgChan(ctx)

	return &clientProtocol{
		ch:     recvChan,
		rc:     rc,
		sideID: sideID,
		appID:  appID,
	}
}

func (cc *clientProtocol) WritePake(ctx context.Context, code string) error {
	pw := gospake2.NewPassword(code)
	spake := gospake2.SPAKE2Symmetric(pw, gospake2.NewIdentityS(cc.appID))
	cc.spake = &spake
	pakeMsgBody := cc.spake.Start()

	pm := pakeMsg{
		Body: hex.EncodeToString(pakeMsgBody),
	}

	return cc.rc.AddMessage(ctx, "pake", jsonHexMarshal(pm))
}

func (cc *clientProtocol) ReadPake() error {
	var pake pakeMsg
	err := cc.readPlaintext("pake", &pake)
	if err != nil {
		return err
	}

	otherSidesMsg, err := hex.DecodeString(pake.Body)
	if err != nil {
		return err
	}

	sharedKey, err := cc.spake.Finish(otherSidesMsg)
	if err != nil {
		return err
	}

	cc.sharedKey = sharedKey

	return nil
}

func (cc *clientProtocol) WriteVersion(ctx context.Context) error {
	phase := "version"
	verInfo := genericMessage{
		AppVersions: &appVersionsMsg{},
	}

	jsonOut, err := json.Marshal(verInfo)
	if err != nil {
		return err
	}

	err = sendEncryptedMessage(ctx, cc.rc, jsonOut, cc.sharedKey, cc.sideID, phase)
	return err
}

func (cc *clientProtocol) ReadVersion() (*appVersionsMsg, error) {
	var v appVersionsMsg
	err := cc.openAndUnmarshal("version", &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (cc *clientProtocol) WriteAppData(ctx context.Context, v *genericMessage) error {
	nextPhase := cc.phaseCounter
	cc.phaseCounter++

	jsonOut, err := json.Marshal(v)
	if err != nil {
		return err
	}

	phase := strconv.Itoa(nextPhase)

	return sendEncryptedMessage(ctx, cc.rc, jsonOut, cc.sharedKey, cc.sideID, phase)
}

func (cc *clientProtocol) openAndUnmarshal(phase string, v interface{}) error {
	gotMsg := <-cc.ch
	if gotMsg.Error != nil {
		return gotMsg.Error
	}

	if gotMsg.Phase != phase {
		return fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
	}

	return openAndUnmarshal(v, gotMsg, cc.sharedKey)
}

func (cc *clientProtocol) readPlaintext(phase string, v interface{}) error {
	gotMsg := <-cc.ch
	if gotMsg.Error != nil {
		return gotMsg.Error
	}

	if gotMsg.Phase != phase {
		return fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
	}

	err := jsonHexUnmarshal(gotMsg.Body, &v)
	if err != nil {
		return err
	}

	return nil
}

type collectType int

const (
	collectOffer collectType = iota + 1
	collectTransit
	collectAnswer
)

func (cc *clientProtocol) Collect(msgTypes ...collectType) (*msgCollector, error) {
	collector := &msgCollector{
		sharedKey: cc.sharedKey,
	}

	for _, mt := range msgTypes {
		switch mt {
		case collectOffer:
			collector.collectOffer = true
		case collectTransit:
			collector.collectTransit = true
		case collectAnswer:
			collector.collectAnswer = true
		default:
			return nil, fmt.Errorf("Unknown collect msg type %d", msgTypes)
		}
	}

	err := collector.collect(cc.ch)
	if err != nil {
		return nil, err
	}
	return collector, nil
}
