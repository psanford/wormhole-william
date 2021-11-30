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
	"reflect"
	"strconv"
	"strings"
	"sync"

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

	// VerifierOk specifies an optional hook to be called before
	// transmitting/receiving the encrypted payload.
	//
	// If VerifierOk is non-nil it will be called after the PAKE
	// hand-shake has succeeded passing in the verifier code. Callers
	// can then prompt the user to confirm the code matches via an out
	// of band mechanism before proceeding with the file transmission.
	// If VerifierOk returns false the transmission will be aborted.
	VerifierOk func(verifier string) bool
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

var errDecryptFailed = errors.New("decrypt message failed")

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

func deriveVerifier(key []byte) []byte {
	purpose := "wormhole:verifier"

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

func (m *offerMsg) Type() collectType {
	return collectOffer
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
	Error       *string         `json:"error,omitempty"`
}

type appVersionsMsg struct {
}

type answerMsg struct {
	MessageAck string `json:"message_ack,omitempty"`
	FileAck    string `json:"file_ack,omitempty"`
}

func (m *answerMsg) Type() collectType {
	return collectAnswer
}

type collectable interface {
	Type() collectType
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

func (m *transitMsg) Type() collectType {
	return collectTransit
}

type msgCollector struct {
	sharedKey      []byte
	collectOffer   bool
	collectTransit bool
	collectAnswer  bool

	subscribe chan *collectSubscription

	closeMu sync.Mutex
	closed  bool
	done    chan error
}

func newMsgCollector(sharedKey []byte) *msgCollector {
	return &msgCollector{
		sharedKey: sharedKey,
		subscribe: make(chan *collectSubscription),
		done:      make(chan error, 1),
	}
}

func (c *msgCollector) close() {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
}

func (c *msgCollector) closeWithErr(err error) {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if !c.closed {
		c.closed = true
		c.done <- err
		close(c.done)
	}
}

func (c *msgCollector) waitFor(msg collectable) error {
	if reflect.ValueOf(msg).Kind() != reflect.Ptr {
		return errors.New("you must pass waitFor a pointer to a struct")
	}
	sub := collectSubscription{
		collectMsg: msg,
		result:     make(chan collectResult, 1),
	}

	select {
	case err := <-c.done:
		if err != nil {
			return err
		}
		return errors.New("msgCollector closed")
	case c.subscribe <- &sub:
	}

	result := <-sub.result
	if result.err != nil {
		return result.err
	}

	dst := reflect.ValueOf(msg).Elem()
	src := reflect.ValueOf(result.result).Elem()

	dst.Set(src)

	return nil
}

type collectResult struct {
	err    error
	result collectable
}

type collectSubscription struct {
	collectMsg collectable
	result     chan collectResult
}

func (c *msgCollector) collect(ch <-chan rendezvous.MailboxEvent) {
	pendingMsgs := make(map[collectType]collectable)
	waiters := make(map[collectType]*collectSubscription)

	errorResult := func(e error) {
		c.closeWithErr(e)

		for t, waiter := range waiters {
			waiter.result <- collectResult{
				err: e,
			}

			delete(waiters, t)
		}
	}

	for {
		select {
		case <-c.done:
			return
		case sub := <-c.subscribe:
			collectType := sub.collectMsg.Type()

			if m := pendingMsgs[collectType]; m != nil {
				sub.result <- collectResult{
					result: m,
				}
				delete(pendingMsgs, collectType)
			} else {
				if waiters[collectType] != nil {
					sub.result <- collectResult{
						err: errors.New("there is already a pending collect request for this type"),
					}
				} else {
					waiters[collectType] = sub
				}
			}
		case gotMsg, ok := <-ch:
			if !ok {
				c.close()
				return
			}
			if gotMsg.Error != nil {
				errorResult(gotMsg.Error)
				return
			}

			if _, err := strconv.Atoi(gotMsg.Phase); err != nil {
				errorResult(fmt.Errorf("got unexpected phase: %s", gotMsg.Phase))
				return
			}

			var msg genericMessage
			err := openAndUnmarshal(&msg, gotMsg, c.sharedKey)
			if err != nil {
				errorResult(err)
				return
			}

			var resultMsg collectable
			var t collectType
			if msg.Offer != nil {
				t = collectOffer
				resultMsg = msg.Offer
			} else if msg.Transit != nil {
				t = collectTransit
				resultMsg = msg.Transit
			} else if msg.Answer != nil {
				t = collectAnswer
				resultMsg = msg.Answer
			} else if msg.Error != nil {
				errorResult(fmt.Errorf("TransferError: %s", *msg.Error))
				return
			} else {
				continue
			}

			if sub := waiters[t]; sub != nil {
				sub.result <- collectResult{
					result: resultMsg,
				}
				delete(waiters, t)
			} else {
				if pendingMsgs[t] != nil {
					errorResult(fmt.Errorf("got multiple messages of type %s", t))
					return
				}
				pendingMsgs[t] = resultMsg
			}
		}
	}
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

func (cc *clientProtocol) ReadPake(ctx context.Context) error {
	var pake pakeMsg
	err := cc.readPlaintext(ctx, "pake", &pake)
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

func (cc *clientProtocol) Verifier() ([]byte, error) {
	if cc.sharedKey == nil {
		return nil, errors.New("shared key not established yet")
	}

	return deriveVerifier(cc.sharedKey), nil
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
		return fmt.Errorf("got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
	}

	return openAndUnmarshal(v, gotMsg, cc.sharedKey)
}

func (cc *clientProtocol) readPlaintext(ctx context.Context, phase string, v interface{}) error {
	var gotMsg rendezvous.MailboxEvent
	select {
	case gotMsg = <-cc.ch:
	case <-ctx.Done():
		return ctx.Err()
	}
	if gotMsg.Error != nil {
		return gotMsg.Error
	}

	if gotMsg.Phase != phase {
		return fmt.Errorf("got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
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

func (ct collectType) String() string {
	switch ct {
	case collectOffer:
		return "Offer"
	case collectTransit:
		return "Transit"
	case collectAnswer:
		return "Answer"
	default:
		return fmt.Sprintf("collectTypeUnkown<%d>", ct)
	}
}

func (cc *clientProtocol) Collect(msgTypes ...collectType) (*msgCollector, error) {
	collector := newMsgCollector(cc.sharedKey)

	for _, mt := range msgTypes {
		switch mt {
		case collectOffer:
			collector.collectOffer = true
		case collectTransit:
			collector.collectTransit = true
		case collectAnswer:
			collector.collectAnswer = true
		default:
			return nil, fmt.Errorf("unknown collect msg type %d", msgTypes)
		}
	}

	go collector.collect(cc.ch)
	return collector, nil
}

func nameplateFromCode(code string) (string, error) {
	nameplate := strings.SplitN(code, "-", 2)[0]

	_, err := strconv.Atoi(nameplate)
	if err != nil {
		return "", errors.New("non-numeric nameplate")
	}

	return nameplate, nil
}
