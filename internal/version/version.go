// Package version carries build identity.
package version

// Version is the release version. It is overridden at build time with
// -ldflags "-X github.com/nizartuanku/auditlight/internal/version.Version=x.y.z".
var Version = "0.3.0"

// Product is the display name.
const Product = "AuditLight"

// Tagline is the one-line description used in the UI and reports.
const Tagline = "Self-hosted security assessment and audit reporting — detection only."

// DefaultPort is the dashboard port for this product in the Hexward line.
const DefaultPort = 8431
