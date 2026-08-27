// Command auditlight runs the AuditLight assessment console.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/notify"
	"github.com/nizartuanku/auditlight/internal/orchestrator"
	"github.com/nizartuanku/auditlight/internal/report"
	"github.com/nizartuanku/auditlight/internal/schedule"
	"github.com/nizartuanku/auditlight/internal/store"
	"github.com/nizartuanku/auditlight/internal/version"
	"github.com/nizartuanku/auditlight/internal/webui"
)

func main() {
	var (
		addr        = flag.String("listen", fmt.Sprintf("127.0.0.1:%d", version.DefaultPort), "address to listen on")
		dataDir     = flag.String("data", defaultDataDir(), "directory for job data")
		licenceKey  = flag.String("license", os.Getenv("AUDITLIGHT_LICENSE"), "licence key (or set AUDITLIGHT_LICENSE)")
		firm        = flag.String("firm", "", "firm name shown on reports (paid tiers)")
		contact     = flag.String("contact", "", "contact line shown in the report footer (paid tiers)")
		whiteLabel  = flag.Bool("white-label", false, "replace the AuditLight name on reports with the firm name (Team tier)")
		showVersion = flag.Bool("version", false, "print version and exit")
		inMemory    = flag.Bool("memory", false, "keep jobs in memory only; nothing is written to disk")
		consoleURL  = flag.String("console-url", "", "base URL used in notification links, e.g. https://audit.example.internal")
		smtpHost    = flag.String("smtp-host", "", "SMTP host for e-mail notifications")
		smtpPort    = flag.Int("smtp-port", 587, "SMTP port")
		smtpUser    = flag.String("smtp-user", "", "SMTP username")
		smtpPass    = flag.String("smtp-pass", os.Getenv("AUDITLIGHT_SMTP_PASS"), "SMTP password (or set AUDITLIGHT_SMTP_PASS)")
		smtpFrom    = flag.String("smtp-from", "", "From address for notifications")
		smtpTLS     = flag.Bool("smtp-starttls", true, "upgrade the SMTP connection with STARTTLS")
		noSchedule  = flag.Bool("no-schedule", false, "do not run scheduled re-assessments")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s\n", version.Product, version.Version)
		return
	}

	lic := license.Resolve(*licenceKey)

	var st store.Store
	if *inMemory {
		st = store.NewMem()
	} else {
		fs, err := store.NewFile(*dataDir)
		if err != nil {
			log.Fatalf("auditlight: %v", err)
		}
		st = fs
	}
	defer st.Close()

	sender := notify.New(notify.SMTPConfig{
		Host: *smtpHost, Port: *smtpPort, Username: *smtpUser,
		Password: *smtpPass, From: *smtpFrom, StartTLS: *smtpTLS,
	})
	runner := orchestrator.New(st, lic).WithNotifications(sender, *consoleURL)
	srv := webui.New(runner, st, report.Branding{
		Firm: *firm, Contact: *contact, WhiteLabel: *whiteLabel,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scheduling := lic.Caps.Reassessment && !*noSchedule
	if scheduling {
		sched := schedule.New(runner, time.Minute, log.New(os.Stdout, "", log.LstdFlags))
		go sched.Start(ctx)
	}

	banner(lic, *addr, *dataDir, *inMemory, scheduling, runner)

	if err := webui.Listen(ctx, *addr, srv.Handler()); err != nil && err != http.ErrServerClosed {
		log.Fatalf("auditlight: %v", err)
	}
}

func banner(lic license.State, addr, dataDir string, inMemory, scheduling bool, runner *orchestrator.Runner) {
	native, present, missing := 0, 0, 0
	for _, c := range runner.Registry().Capabilities() {
		switch {
		case c.Kind == "native":
			native++
		case c.Available:
			present++
		default:
			missing++
		}
	}
	url := addr
	if strings.HasPrefix(url, ":") {
		url = "127.0.0.1" + url
	}
	fmt.Printf("%s %s — %s\n", version.Product, version.Version, version.Tagline)
	fmt.Printf("  licence   %s\n", lic.Notice)
	fmt.Printf("  checks    %d built in, %d external tool(s) found, %d absent\n", native, present, missing)
	if inMemory {
		fmt.Printf("  storage   in memory only — nothing is written to disk\n")
	} else {
		fmt.Printf("  storage   %s\n", dataDir)
	}
	if scheduling {
		defs, err := runner.Store().ListDefinitions("")
		n := 0
		if err == nil {
			for _, d := range defs {
				if d.Enabled && d.IntervalDays > 0 {
					n++
				}
			}
		}
		fmt.Printf("  schedule  on — %d recurring assessment(s)\n", n)
	} else if !lic.Caps.Reassessment {
		fmt.Printf("  schedule  off — recurring assessments need a paid licence\n")
	} else {
		fmt.Printf("  schedule  off — disabled with -no-schedule\n")
	}
	fmt.Printf("  console   http://%s\n\n", url)
}

func defaultDataDir() string {
	if d := os.Getenv("AUDITLIGHT_DATA"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".auditlight"
	}
	return filepath.Join(home, ".auditlight")
}
