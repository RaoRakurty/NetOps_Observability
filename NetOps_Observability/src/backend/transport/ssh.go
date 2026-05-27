package transport

import "context"

// SSHDialer is a placeholder for NETCONF-over-SSH connectivity.
type SSHDialer struct{}

func (SSHDialer) Name() string                                      { return "ssh" }
func (SSHDialer) Dial(_ context.Context, _ string) (Session, error) { return nopSession{}, nil }
