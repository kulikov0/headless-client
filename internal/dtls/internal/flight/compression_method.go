// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import "github.com/kulikov0/headless-client/internal/dtls/pkg/protocol"

// DefaultCompressionMethods returns the supported compression methods.
func DefaultCompressionMethods() []*protocol.CompressionMethod {
	return []*protocol.CompressionMethod{
		{},
	}
}
