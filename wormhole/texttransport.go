package wormhole

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/psanford/wormhole-william/random"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
	"salsa.debian.org/vasudev/gospake2"
)

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
		verInfo := genericMessage{
			AppVersions: &appVersionsMsg{},
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

		var gotVersion genericMessage
		err = openAndUnmarshal(&gotVersion, gotMsg, sharedKey)
		if err != nil {
			sendErr(err)
			return
		}
		if gotVersion.AppVersions == nil {
			sendErr(errors.New("Expected app_versions message"))
			return

		}

		phase = "0"
		offer := genericMessage{
			Offer: &offerMsg{
				Message: &msg,
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

		var answer genericMessage
		err = openAndUnmarshal(&answer, gotMsg, sharedKey)
		if err != nil {
			sendErr(err)
			return
		}

		if answer.Answer != nil && answer.Answer.MessageAck == "ok" {
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
	verInfo := genericMessage{
		AppVersions: &appVersionsMsg{},
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

	var gotVersion genericMessage
	err = openAndUnmarshal(&gotVersion, gotMsg, sharedKey)
	if err != nil {
		return "", err
	}
	if gotVersion.AppVersions == nil {
		return "", errors.New("Expected app_versions message")
	}

	phase = "0"
	gotMsg = <-recvChan
	if gotMsg.Error != nil {
		return "", gotMsg.Error
	}
	if gotMsg.Phase != phase {
		return "", fmt.Errorf("Got unexpected phase while waiting for %s: %s", phase, gotMsg.Phase)
	}

	var offer genericMessage
	err = openAndUnmarshal(&offer, gotMsg, sharedKey)
	if err != nil {
		return "", err
	}

	if offer.Offer == nil || offer.Offer.Message == nil {
		return "", errors.New("Got non-text offer")
	}

	answer := genericMessage{
		Answer: &answerMsg{
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

	return *offer.Offer.Message, nil
}
