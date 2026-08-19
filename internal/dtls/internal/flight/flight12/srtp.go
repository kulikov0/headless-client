// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"fmt"

	dtlserrors "github.com/kulikov0/headlessclient/internal/dtls/internal/errors"
	"github.com/kulikov0/headlessclient/internal/dtls/internal/extensionnegotiation"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/alert"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/extension"
)

func validateServerSRTP(
	snapshot extensionnegotiation.ClientHelloSnapshot,
	responses []extension.Value,
	localProfiles []extension.SRTPProtectionProfile,
	want extensionnegotiation.SRTPDecision,
) error {
	got, err := extensionnegotiation.ValidateSRTPSelection(snapshot, responses, localProfiles)
	if err != nil {
		return err
	}
	if got.ProtectionProfile != want.ProtectionProfile ||
		!bytes.Equal(got.MasterKeyIdentifier, want.MasterKeyIdentifier) {
		return newSRTPError(dtlserrors.ErrInvalidServerHello, alert.InternalError)
	}

	return nil
}

func appendSRTPSelection(
	extensions []extension.Value,
	decision extensionnegotiation.SRTPDecision,
) []extension.Value {
	if decision.ProtectionProfile == 0 {
		return extensions
	}

	return append(extensions, &extension.SRTPSelection{
		ProtectionProfile:   decision.ProtectionProfile,
		MasterKeyIdentifier: bytes.Clone(decision.MasterKeyIdentifier),
	})
}

func newSRTPError(kind error, description alert.Description) error {
	return fmt.Errorf("%w: %w", kind, &alert.Alert{Level: alert.Fatal, Description: description})
}
