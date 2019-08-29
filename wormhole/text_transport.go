package wormhole

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/psanford/wormhole-william/random"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
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

	clientProto := newClientProtocol(ctx, rc, sideID, appID)

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

		err = clientProto.WritePake(ctx, pwStr)
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.ReadPake()
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.WriteVersion(ctx)
		if err != nil {
			sendErr(err)
			return
		}

		_, err = clientProto.ReadVersion()
		if err != nil {
			sendErr(err)
			return
		}

		offer := &genericMessage{
			Offer: &offerMsg{
				Message: &msg,
			},
		}
		err = clientProto.WriteAppData(ctx, offer)
		if err != nil {
			sendErr(err)
			return
		}

		collector, err := clientProto.Collect(collectAnswer)
		if err != nil {
			sendErr(err)
			return
		}

		if collector.answer.MessageAck == "ok" {
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

	clientProto := newClientProtocol(ctx, rc, sideID, appID)

	err = clientProto.WritePake(ctx, code)
	if err != nil {
		return "", err
	}

	err = clientProto.ReadPake()
	if err != nil {
		return "", err
	}

	err = clientProto.WriteVersion(ctx)
	if err != nil {
		return "", err
	}

	_, err = clientProto.ReadVersion()
	if err != nil {
		return "", err
	}

	collector, err := clientProto.Collect(collectOffer)
	if err != nil {
		return "", err
	}

	if collector.offer.Message == nil {
		return "", errors.New("Got non-text offer")
	}

	answer := genericMessage{
		Answer: &answerMsg{
			MessageAck: "ok",
		},
	}

	err = clientProto.WriteAppData(ctx, &answer)
	if err != nil {
		return "", err
	}

	return *collector.offer.Message, nil
}
