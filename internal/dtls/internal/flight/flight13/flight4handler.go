// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"
	"crypto"
	"slices"

	dtlsconfig "github.com/kulikov0/headless-client/internal/dtls/internal/config"
	dtlserrors "github.com/kulikov0/headless-client/internal/dtls/internal/errors"
	dtlsflight "github.com/kulikov0/headless-client/internal/dtls/internal/flight"
	"github.com/kulikov0/headless-client/internal/dtls/internal/negotiation"
	dtlsstate "github.com/kulikov0/headless-client/internal/dtls/internal/state"
	cryptosuite "github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/ciphersuite"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/elliptic"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/prf"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/signaturehash"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/alert"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/extension"
	extension13 "github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/extension/dtls13"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/handshake"
)

// flight4Parse processes the client's protected final flight. The parser is
// keyed by the server's current flight (Flight 4), even tho the messages on
// the wire are the client's Flight 5.
func flight4Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	protectedFlight := pullProtectedHandshakeFlight(
		flightCtx.cache,
		[]dtlsflight.HandshakeCachePullRule{
			{Typ: handshake.TypeCertificate, Epoch: EpochHandshake, IsClient: true, Optional: true},
			{Typ: handshake.TypeCertificateVerify, Epoch: EpochHandshake, IsClient: true, Optional: true},
			{Typ: handshake.TypeFinished, Epoch: EpochHandshake, IsClient: true, Optional: false},
		},
		flightCtx.state.HandshakeRecvSequence,
	)
	if !protectedFlight.ready {
		return 0, nil, nil
	}
	if protectedFlight.failure != nil {
		return 0, protectedFlight.failure.alert, protectedFlight.failure.err
	}

	if flightCtx.protectedHandshakeHandler == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if err := flightCtx.protectedHandshakeHandler(flightCtx.state.CipherSuite, protectedFlight.items); err != nil {
		failure := protectedFlightParseFailure(err)

		return 0, failure.alert, failure.err
	}
	flightCtx.state.HandshakeRecvSequence = protectedFlight.nextHandshakeSequence

	// Returning the current flight marks the server's last receive flight.
	return Flight4, nil, nil
}

func selectClientKeyShare(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) bool {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		return false
	}
	state.SelectedGroup = selectedGroup

	return true
}

func generateClientKeyShareSecret(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig) *clientHelloExtensionFailure {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		if state.RemoteGroups != nil {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrNoSupportedEllipticCurves)
		}

		return nil
	}
	state.SelectedGroup = selectedGroup

	selectedEntry, ok := clientKeyShareForGroup(state, selectedGroup)
	if !ok {
		return newClientHelloExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
	}

	if needsClientKeypair(state) {
		keypair, err := elliptic.GenerateKeypairForPeer(state.SelectedGroup, selectedEntry.KeyExchange)
		if err != nil {
			return newClientHelloExtensionFailure(alert.IllegalParameter, err)
		}
		state.LocalKeypair = keypair
	}

	keyAgreementSecret, err := prf.PreMasterSecret(selectedEntry.KeyExchange, state.LocalKeypair.PrivateKey, state.SelectedGroup)
	if err != nil {
		return newClientHelloExtensionFailure(alert.IllegalParameter, err)
	}
	state.KeyAgreementSecret = keyAgreementSecret

	return nil
}

func matchingClientKeyShare(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig) (extension13.KeyShareEntry, bool) {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		return extension13.KeyShareEntry{}, false
	}

	return clientKeyShareForGroup(state, selectedGroup)
}

func preferredClientGroup(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) (elliptic.Curve, bool) {
	if state.RemoteGroups == nil {
		return 0, false
	}

	for _, group := range cfg.EllipticCurves {
		if slices.Contains(state.RemoteGroups, group) {
			return group, true
		}
	}

	return 0, false
}

func clientKeyShareForGroup(
	state *dtlsstate.State13,
	group elliptic.Curve,
) (extension13.KeyShareEntry, bool) {
	if !state.HasRemoteKeyEntries {
		return extension13.KeyShareEntry{}, false
	}
	for _, entry := range state.RemoteKeyEntries {
		if entry.Group == group {
			return entry, true
		}
	}

	return extension13.KeyShareEntry{}, false
}

func needsClientKeypair(state *dtlsstate.State13) bool {
	return state.LocalKeypair == nil || state.LocalKeypair.Curve != state.SelectedGroup || state.SelectedGroup == elliptic.X25519MLKEM768
}

func flight4Generate( //nolint:cyclop
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg

	if state.CipherSuite == nil {
		return nil, nil, dtlserrors.ErrCipherSuiteUnset
	}
	if state.LocalKeypair == nil {
		return nil, nil, dtlserrors.ErrServerKeyShareMissing
	}

	certificate, err := cfg.GetCertificate(&dtlsconfig.ClientHelloInfo{ServerName: state.ServerName, CipherSuites: []cryptosuite.ID{state.CipherSuite.ID()}, RandomBytes: state.RemoteRandom.RandomBytes})
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
	}
	if certificate == nil || len(certificate.Certificate) == 0 {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure},
			dtlserrors.ErrNoCertificates
	}

	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure},
			dtlserrors.ErrInvalidPrivateKey
	}

	commonSignatureSchemes := make([]signaturehash.Algorithm, 0, len(state.RemoteSignatureSchemes))
	for _, remote := range state.RemoteSignatureSchemes {
		if slices.Contains(cfg.LocalSignatureSchemes, remote) {
			commonSignatureSchemes = append(commonSignatureSchemes, remote)
		}
	}

	signatureScheme, err := signaturehash.SelectSignatureScheme(
		commonSignatureSchemes,
		signer,
		protocol.Version1_3,
	)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
	}

	cipherSuiteID := uint16(state.CipherSuite.ID())
	serverHelloExtensions := []extension.Value{
		&extension13.SelectedVersion{
			Version: protocol.Version1_3,
		},
	}
	serverHelloExtensions = append(serverHelloExtensions, &extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: state.LocalKeypair.Curve, KeyExchange: state.LocalKeypair.PublicKey}})
	offer := state.RemoteClientHelloSnapshots.Current()
	srtpDecision, err := negotiation.NegotiateSRTP(offer, cfg.LocalSRTPProtectionProfiles, cfg.LocalSRTPMasterKeyIdentifier)
	if err != nil {
		return nil, nil, err
	}
	if cfg.ConnectionIDGenerator != nil && offer.Offered(extension.TypeConnectionID) {
		localCID := state.LocalConnectionID()
		if !state.CID.Negotiated {
			localCID, err = cfg.GenerateConnectionID()
			if err != nil {
				return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			localCID = bytes.Clone(localCID)
		}
		serverHelloExtensions = dtlsflight.AppendConnectionIDExtensions(serverHelloExtensions, localCID, cfg.EnableRRC && offer.Offered(extension.TypeReturnRoutabilityCheck))
	}
	serverHelloMessage := &handshake.MessageServerHello{Version: protocol.Version1_2, Random: state.LocalRandom, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0], Extensions: serverHelloExtensions}
	serverHelloMessage, err = finalizeServerHello13(serverHelloMessage, cfg)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if _, err = serverHelloMessage.Marshal(); err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	decision := negotiation.DecideConnectionID(offer, serverHelloMessage.Extensions)

	serverHello := &dtlsflight.Outbound{
		Content: &handshake.Handshake{Message: serverHelloMessage},
	}

	encryptedExtensionsList := []extension.Value{}
	if srtpDecision.ProtectionProfile != 0 {
		encryptedExtensionsList = append(encryptedExtensionsList, &extension.SRTPSelection{ProtectionProfile: srtpDecision.ProtectionProfile, MasterKeyIdentifier: bytes.Clone(srtpDecision.MasterKeyIdentifier)})
	}
	messageExtensions := handshake.MessageEncryptedExtensions{}
	messageExtensions.Extensions = encryptedExtensionsList
	encryptedExtensions := HandshakePacket(&messageExtensions)

	pkts := []*dtlsflight.Outbound{
		serverHello,
		encryptedExtensions,
	}
	if cfg.ClientAuth > dtlsconfig.NoClientCert {
		// RFC 8446 Section 4.3.2 requires signature_algorithms in the request.
		// https://www.rfc-editor.org/rfc/rfc9147.html#section-5.1
		// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.3.2
		certificateRequestExtensions := []extension.Value{&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)}}
		if cfg.ClientCAs != nil {
			certificateRequestExtensions = append(certificateRequestExtensions, &extension13.CertificateAuthorities{
				// nolint:staticcheck // ignoring tlsCert.RootCAs.Subjects is deprecated ERR
				// because cert does not come from SystemCertPool and it's ok if certificate
				// authorities is empty.
				Authorities: cfg.ClientCAs.Subjects(),
			})
		}
		m := handshake.MessageCertificateRequest13{}
		m.Extensions = certificateRequestExtensions
		pkts = append(pkts, HandshakePacket(&m))
	}
	pkts = append(pkts,
		HandshakePacket(&handshake.MessageCertificate13{
			CertificateList: certificateEntries(certificate.Certificate),
		}),
		CertificateVerifyPacket(
			&handshake.MessageCertificateVerify{
				HashAlgorithm:      signatureScheme.Hash,
				SignatureAlgorithm: signatureScheme.Signature,
			},
			signer,
		),
		HandshakePacket(&handshake.MessageFinished{}),
	)
	state.CommitNegotiatedExtensions(decision)
	dtlsflight.CommitSRTP(state.Common, srtpDecision)

	return pkts, nil, nil
}

// finalizeServerHello13 applies the server hello hook on the DTLS 1.3 path.
// Upstream applies the hook on the 1.2 path only, through
// dtlsflight.FinalizeServerHello, which rejects a 1.3 server hello because
// negotiation.ValidateServerHello12Context reads supported_versions as a
// message that is not a 1.2 server hello.
//
// The hook may reorder the extensions and nothing else. Reordering is the only
// reason this module hooks the message, and an extension the hook adds or
// drops would change a negotiation the hook cannot see.
func finalizeServerHello13(
	base *handshake.MessageServerHello,
	cfg *dtlsconfig.HandshakeConfig,
) (*handshake.MessageServerHello, error) {
	if cfg.ServerHelloMessageHook == nil {
		return base, nil
	}
	hooked, ok := cfg.ServerHelloMessageHook(*base).(*handshake.MessageServerHello)
	if !ok || !slices.Equal(extensionTypes(base.Extensions), extensionTypes(hooked.Extensions)) {
		return nil, dtlserrors.ErrInvalidServerHello
	}
	if err := dtlsflight.ValidateHookedConnectionIDLength(hooked.Extensions, cfg, true); err != nil {
		return nil, err
	}

	return hooked, nil
}

// extensionTypes returns the extension types in ascending order, so two sets
// compare equal whatever order the hook left them in.
func extensionTypes(values []extension.Value) []extension.Type {
	types := make([]extension.Type, 0, len(values))
	for _, value := range values {
		types = append(types, value.ExtensionType())
	}
	slices.Sort(types)

	return types
}
