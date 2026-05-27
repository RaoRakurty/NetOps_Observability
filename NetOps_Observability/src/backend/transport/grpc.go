package transport

import "context"

// GRPCDialer is a placeholder for gNMI / streaming-telemetry connectivity.
type GRPCDialer struct{}

func (GRPCDialer) Name() string                                      { return "grpc" }
func (GRPCDialer) Dial(_ context.Context, _ string) (Session, error) { return nopSession{}, nil }
