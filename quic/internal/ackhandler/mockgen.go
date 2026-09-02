//go:build gomock || generate

package ackhandler

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\"  -package ackhandler -destination mock_ecn_handler_test.go github.com/kulikov0/headless-client/quic/internal/ackhandler ECNHandler"
type ECNHandler = ecnHandler
