package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/client"
	generatedClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	_ "github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"strconv"
)

const (
	defaultRekorServerURL = "https://rekor.sigstore.dev"
)

type RekorClient struct {
	*generatedClient.Rekor
	Verifier signature.Verifier
	Context  context.Context
}

func NewRekorClient(ctx context.Context) (*RekorClient, error) {
	rekorClient, err := client.GetRekorClient(defaultRekorServerURL)
	if err != nil {
		return nil, err
	}

	pubkeyResp, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(pubkeyResp.Payload))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse public key")
	}

	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &RekorClient{rekorClient, verifier, ctx}, nil
}

func (rc *RekorClient) GetEntryByUUID(uuid string) (map[string]interface{}, error) {
	params := entries.NewGetLogEntryByUUIDParams()
	params.Context = rc.Context
	params.EntryUUID = uuid

	resp, err := rc.Entries.GetLogEntryByUUID(params)
	if err != nil {
		panic(err)
	}

	var e models.LogEntryAnon
	for k, entry := range resp.Payload {
		e = entry
		if err := verify.VerifyLogEntry(rc.Context, &e, rc.Verifier); err != nil {
			panic(fmt.Errorf("unable to verify entry was added to log: %w", err))
		}

		return parseEntry(k, entry)
	}
	return nil, err
}

func (rc *RekorClient) GetEntriesByLogIndex(logIndex string) (map[string]interface{}, error) {
	params := entries.NewGetLogEntryByIndexParams()
	logIndexInt, err := strconv.ParseInt(logIndex, 10, 0)
	if err != nil {
		panic(err)
	}
	params.LogIndex = logIndexInt

	resp, err := rc.Entries.GetLogEntryByIndex(params)
	if err != nil {
		panic(err)
	}

	var e models.LogEntryAnon
	for k, entry := range resp.Payload {
		e = entry
		if err := verify.VerifyLogEntry(rc.Context, &e, rc.Verifier); err != nil {
			panic(fmt.Errorf("unable to verify entry was added to log: %w", err))
		}

		return parseEntry(k, entry)
	}
	return nil, err
}

func (rc *RekorClient) GetEntriesByHash(hash string) (map[string]interface{}, error) {
	sip := index.NewSearchIndexParams()
	sip.Query = &models.SearchIndex{
		Hash: hash,
	}
	resp, err := rc.Index.SearchIndex(sip)
	if err != nil {
		panic(err)
	}

	for _, uuid := range resp.Payload {
		params := entries.NewGetLogEntryByUUIDParams()
		params.EntryUUID = uuid

		resp, err := rc.Entries.GetLogEntryByUUID(params)
		if err != nil {
			panic(err)
		}
		var e models.LogEntryAnon
		for ix, entry := range resp.Payload {
			if ix != uuid {
				panic(fmt.Errorf("expected key %s, got %s", uuid, ix))
			}
			// verify log entry
			e = entry
			if err := verify.VerifyLogEntry(rc.Context, &e, rc.Verifier); err != nil {
				panic(fmt.Errorf("unable to verify entry was added to log: %w", err))
			}
			return parseEntry(ix, entry)
		}
	}
	return nil, err

}

func parseEntry(uuid string, e models.LogEntryAnon) (map[string]interface{}, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.CreateVersionedEntry(pe)
	if err != nil {
		return nil, err
	}
	hashedRekordEntry, ok := eimpl.(*hashedrekord.V001Entry)
	if !ok {
		return nil, errors.New("cannot unmarshal non Helm v0.0.1 type")
	}

	obj := map[string]interface{}{
		"Body":           hashedRekordEntry,
		"uuid":           uuid,
		"IntegratedTime": *e.IntegratedTime,
		"LogIndex":       int(*e.LogIndex),
		"LogID":          *e.LogID,
	}

	if e.Attestation != nil {
		obj["Attestation"] = string(e.Attestation.Data)
	}

	return obj, nil
}
