package transport

import "context"

// SNMPDialer is a placeholder. Replace with gosnmp.GoSNMP configuration
// when the SNMP collector is fleshed out.
type SNMPDialer struct{}

func (SNMPDialer) Name() string                                      { return "snmp" }
func (SNMPDialer) Dial(_ context.Context, _ string) (Session, error) { return nopSession{}, nil }

type nopSession struct{}

func (nopSession) Close() error { return nil }
