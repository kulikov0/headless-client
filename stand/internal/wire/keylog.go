package wire

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
)

const (
	ClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	ClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	MasterSecret    = "CLIENT_RANDOM"
)

// label -> hex client random -> secret
type Keys map[string]map[string][]byte

func ReadKeys(path string) (Keys, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Keys{}, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseKeys(data), nil
}

func ParseKeys(data []byte) Keys {
	keys := Keys{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			continue
		}
		if keys[fields[0]] == nil {
			keys[fields[0]] = map[string][]byte{}
		}
		keys[fields[0]][strings.ToLower(fields[1])] = secret
	}
	return keys
}

func (k Keys) Secret(label string, clientRandom []byte) []byte {
	return k[label][hex.EncodeToString(clientRandom)]
}
