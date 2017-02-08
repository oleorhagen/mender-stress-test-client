package main

import (
	"strings"

	"github.com/mendersoftware/log"
	"github.com/mendersoftware/mender/client"
	"github.com/pkg/errors"
)

func (m *FakeMenderAuthManager) MakeAuthRequest() (*client.AuthRequest, error) {
	var err error
	authd := client.AuthReqData{}

	idata := string(m.idSrc)

	authd.IdData = idata

	// fill device public key
	authd.Pubkey, err = m.keyStore.PublicPEM()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to obtain device public key")
	}

	tentok := strings.TrimSpace(string(m.tenantToken))

	log.Debugf("tenant token: %s", tentok)

	// fill tenant token
	authd.TenantToken = string(tentok)

	log.Debugf("authorization data: %v", authd)

	reqdata, err := authd.ToBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert auth request data")
	}

	// generate signature
	sig, err := m.keyStore.Sign(reqdata)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to sign auth request")
	}

	return &client.AuthRequest{
		Data:      reqdata,
		Token:     client.AuthToken(tentok),
		Signature: sig,
	}, nil
}

func (m *FakeMenderAuthManager) RecvAuthResponse(data []byte) error {
	return nil
}
