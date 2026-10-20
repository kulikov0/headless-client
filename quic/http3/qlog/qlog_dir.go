package qlog

import (
	"context"

	"github.com/megamen32/headless-client/quic"
	"github.com/megamen32/headless-client/quic/qlog"
	"github.com/megamen32/headless-client/quic/qlogwriter"
)

const EventSchema = "urn:ietf:params:qlog:events:http3-12"

func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracerWithSchemas(ctx, isClient, connID, []string{qlog.EventSchema, EventSchema})
}
