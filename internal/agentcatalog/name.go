package agentcatalog

import "fmt"

// maxNameLen bounds an agent name. Names become filenames, so this also keeps
// the composed path well inside every platform's limit.
const maxNameLen = 64

// ValidName reports whether name is a usable agent name: 1 to 64 bytes of
// lowercase kebab-case, not starting or ending with a hyphen, and not a Windows
// reserved device basename. It is checked before any filesystem access, so a
// traversal attempt never reaches a directory read.
//
// The charset rule already rejects path separators, "..", and a ".md" suffix;
// the suffix is called out separately only to give a better message for the
// most likely mistake.
func ValidName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrAgentName)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: %q is %d bytes, limit is %d", ErrAgentName, name, len(name), maxNameLen)
	}
	if hasMDSuffix(name) {
		return fmt.Errorf("%w: pass the name without the .md extension", ErrAgentName)
	}

	for i := range len(name) {
		if !isNameByte(name[i]) {
			return fmt.Errorf("%w: %q may contain only a-z, 0-9 and '-'", ErrAgentName, name)
		}
	}

	if name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("%w: %q may not start or end with '-'", ErrAgentName, name)
	}
	if isWindowsDevice(name) {
		return fmt.Errorf("%w: %q is a reserved device name on Windows", ErrAgentName, name)
	}

	return nil
}

// hasMDSuffix reports whether name ends in the markdown extension.
func hasMDSuffix(name string) bool {
	const ext = ".md"

	return len(name) > len(ext) && name[len(name)-len(ext):] == ext
}

// isNameByte reports whether b is allowed in an agent name.
func isNameByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-'
}

// isWindowsDevice reports whether name is a reserved Windows device basename.
// Creating or opening one of these on Windows addresses a device rather than a
// file, so they are rejected on every platform to keep behavior identical. A
// switch keeps the set out of package scope (gochecknoglobals).
func isWindowsDevice(name string) bool {
	switch name {
	case "con", "prn", "aux", "nul",
		"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
		"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9":
		return true
	default:
		return false
	}
}
