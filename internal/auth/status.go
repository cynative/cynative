package auth

// ConnectorStatus is the per-connector registration outcome surfaced in the
// startup inventory. Available marks a registered connector; Warn marks an
// available-but-loud posture (e.g. github writes broadened). For an unavailable
// connector, Reason holds the cause and Posture/Identity are empty.
type ConnectorStatus struct {
	Name      string
	Available bool
	Warn      bool
	Posture   string
	Identity  string
	Reason    string
	// Managed is a managed sub-connector folded onto this line (e.g. "eks");
	// empty when none. Display-only; does not enter the system-prompt provider list.
	Managed string
}
