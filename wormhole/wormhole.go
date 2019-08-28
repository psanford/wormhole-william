package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/psanford/wormhole-william/random"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"salsa.debian.org/vasudev/gospake2"
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

// SendText returns nameplate+pass-phrase, result chan, error
func (c *Client) SendText(ctx context.Context, msg string) (string, chan SendResult, error) {

	sideID := random.SideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	_, err := rc.Connect(ctx)
	if err != nil {
		return "", nil, err
	}

	nameplate, err := rc.CreateMailbox(ctx)
	if err != nil {
		return "", nil, err
	}

	pwStr := nameplate + "-" + wordlist.ChooseWords(c.wordCount())

	ch := make(chan SendResult, 1)
	go func() {
		var returnErr error
		defer func() {
			mood := rendezvous.Errory
			if returnErr == nil {
				mood = rendezvous.Happy
			} else if returnErr == errDecryptFailed {
				mood = rendezvous.Scary
			}

			rc.Close(ctx, mood)
		}()

		sendErr := func(err error) {
			ch <- SendResult{
				Error: err,
			}
			returnErr = err
			close(ch)
			return
		}

		pw := gospake2.NewPassword(pwStr)
		spake := gospake2.SPAKE2Symmetric(pw, gospake2.NewIdentityS(appID))
		pakeMsgBody := spake.Start()

		pm := pakeMsg{
			Body: hex.EncodeToString(pakeMsgBody),
		}
		phase := "pake"
		rc.AddMessage(ctx, phase, jsonHexMarshal(pm))

		recvChan := rc.MsgChan(ctx)

		gotMsg := <-recvChan
		if gotMsg.Error != nil {
			sendErr(gotMsg.Error)
			return
		}

		if gotMsg.Phase != phase {
			sendErr(fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase))
			return
		}

		var gotPM pakeMsg
		err = jsonHexUnmarshal(gotMsg.Body, &gotPM)
		if err != nil {
			sendErr(err)
			return
		}

		otherSidesMsg, err := hex.DecodeString(gotPM.Body)
		if err != nil {
			sendErr(err)
			return
		}

		sharedKey, err := spake.Finish(otherSidesMsg)
		if err != nil {
			sendErr(err)
			return
		}

		phase = "version"
		verInfo := versionsMsg{
			AppVersions: make(map[string]interface{}),
		}

		jsonOut, err := json.Marshal(verInfo)
		if err != nil {
			sendErr(err)
			return
		}

		err = sendEncryptedMessage(ctx, rc, jsonOut, sharedKey, sideID, phase)
		if err != nil {
			sendErr(err)
			return
		}

		gotMsg = <-recvChan
		if gotMsg.Error != nil {
			sendErr(gotMsg.Error)
			return
		}

		if gotMsg.Phase != phase {
			sendErr(fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase))
			return
		}

		var gotVersion versionsMsg
		err = openAndUnmarshal(&gotVersion, gotMsg, sharedKey)
		if err != nil {
			sendErr(err)
			return
		}

		phase = "0"
		offer := offerMsgOuter{
			Offer: offerMsgInner{
				Message: msg,
			},
		}
		offerJson, err := json.Marshal(offer)
		if err != nil {
			sendErr(err)
			return
		}

		err = sendEncryptedMessage(ctx, rc, offerJson, sharedKey, sideID, phase)
		if err != nil {
			sendErr(err)
			return
		}

		gotMsg = <-recvChan
		if gotMsg.Error != nil {
			sendErr(gotMsg.Error)
			return
		}
		if gotMsg.Phase != phase {
			sendErr(fmt.Errorf("Got unexpected phase while waiting for phase \"%s\": %s", phase, gotMsg.Phase))
			return
		}

		var answer answerMsgOuter
		err = openAndUnmarshal(&answer, gotMsg, sharedKey)
		if err != nil {
			sendErr(err)
			return
		}

		if answer.Answer.MessageAck == "ok" {
			ch <- SendResult{
				OK: true,
			}
			close(ch)
			return
		} else {
			sendErr(fmt.Errorf("Unexpected answer"))
			return
		}
	}()

	return pwStr, ch, nil
}

func (c *Client) RecvText(ctx context.Context, code string) (message string, returnErr error) {
	sideID := random.SideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	defer func() {
		mood := rendezvous.Errory
		if returnErr == nil {
			mood = rendezvous.Happy
		} else if returnErr == errDecryptFailed {
			mood = rendezvous.Scary
		}

		rc.Close(ctx, mood)
	}()

	_, err := rc.Connect(ctx)
	if err != nil {
		return "", err
	}
	nameplate := strings.SplitN(code, "-", 2)[0]

	err = rc.AttachMailbox(ctx, nameplate)
	if err != nil {
		return "", err
	}
	recvChan := rc.MsgChan(ctx)

	phase := "pake"

	gotMsg := <-recvChan
	if gotMsg.Error != nil {
		return "", gotMsg.Error
	}

	if gotMsg.Phase != phase {
		return "", fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
	}

	var gotPM pakeMsg
	err = jsonHexUnmarshal(gotMsg.Body, &gotPM)
	if err != nil {
		return "", err
	}

	otherSidesMsg, err := hex.DecodeString(gotPM.Body)
	if err != nil {
		return "", err
	}

	pw := gospake2.NewPassword(code)
	spake := gospake2.SPAKE2Symmetric(pw, gospake2.NewIdentityS(appID))
	pakeMsgBody := spake.Start()

	pm := pakeMsg{
		Body: hex.EncodeToString(pakeMsgBody),
	}
	err = rc.AddMessage(ctx, phase, jsonHexMarshal(pm))
	if err != nil {
		return "", err
	}

	sharedKey, err := spake.Finish(otherSidesMsg)
	if err != nil {
		return "", err
	}

	phase = "version"
	verInfo := versionsMsg{
		AppVersions: make(map[string]interface{}),
	}

	jsonOut, err := json.Marshal(verInfo)
	if err != nil {
		return "", err
	}

	err = sendEncryptedMessage(ctx, rc, jsonOut, sharedKey, sideID, phase)
	if err != nil {
		return "", err
	}

	gotMsg = <-recvChan
	if gotMsg.Error != nil {
		return "", gotMsg.Error
	}

	if gotMsg.Phase != phase {
		return "", fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
	}

	var gotVersion versionsMsg
	err = openAndUnmarshal(&gotVersion, gotMsg, sharedKey)
	if err != nil {
		return "", err
	}

	phase = "0"
	gotMsg = <-recvChan
	if gotMsg.Error != nil {
		return "", gotMsg.Error
	}
	if gotMsg.Phase != phase {
		return "", fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
	}

	var offer offerMsgOuter
	err = openAndUnmarshal(&offer, gotMsg, sharedKey)
	if err != nil {
		return "", err
	}

	answer := answerMsgOuter{
		Answer: answerMsgInner{
			MessageAck: "ok",
		},
	}

	answerJson, err := json.Marshal(answer)
	if err != nil {
		return "", err
	}

	err = sendEncryptedMessage(ctx, rc, answerJson, sharedKey, sideID, phase)
	if err != nil {
		return "", err
	}

	return offer.Offer.Message, nil
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

type pakeMsg struct {
	Body string `json:"pake_v1"`
}

type versionsMsg struct {
	AppVersions map[string]interface{} `json:"app_versions"`
}

type offerMsgOuter struct {
	Offer offerMsgInner `json:"offer"`
}

type offerMsgInner struct {
	Message string `json:"message"`
}

type answerMsgOuter struct {
	Answer answerMsgInner `json:"answer"`
}

type answerMsgInner struct {
	MessageAck string `json:"message_ack"`
}

func splitNonce(sealedMsg []byte) (nonce [24]byte, msg []byte) {
	copy(nonce[:], sealedMsg[:24])
	return nonce, sealedMsg[24:]
}
