// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/ciphersuite"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/clientcertificate"
)

// NewTLSEcdheEcdsaWithAes128Ccm constructs a TLS_ECDHE_ECDSA_WITH_AES_128_CCM Cipher.
func NewTLSEcdheEcdsaWithAes128Ccm() *Aes128Ccm {
	return newAes128Ccm(
		clientcertificate.ECDSASign,
		TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		false,
		ciphersuite.CCMTagLength,
		KeyExchangeAlgorithmEcdhe,
		true,
	)
}
