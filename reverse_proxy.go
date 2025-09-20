package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	// Kommandozeilenparameter definieren
	targetIP := flag.String("target", "10.11.120.2", "IP-Adresse des HAN Ports des Smart Meter Gateways")
	listenPort := flag.String("port", "8080", "Port, auf dem der SMGW-Proxy lauschen soll")
	certDir := flag.String("certdir", "./certs", "Verzeichnis zum Speichern der TOFU-Zertifikate")
	logDir := flag.String("logdir", "./logs", "Verzeichnis zum Speichern der Log-Dateien")
	logFile := flag.String("logfile", "proxy.log", "Name der Log-Datei")
	flag.Parse()

	// Sicherstellen, dass das Zertifikatsverzeichnis existiert
	ensureDirectory(*certDir)

	// Sicherstellen, dass das Log-Verzeichnis existiert
	ensureDirectory(*logDir)

	// Log-Datei konfigurieren
	logWriter, err := NewRotatingFileWriter(*logDir, *logFile)
	if err != nil {
		log.Fatalf("Fehler beim Erstellen des Log-Writers: %v", err)
	}

	// Log auf Datei und Konsole umleiten
	log.SetOutput(io.MultiWriter(os.Stdout, logWriter))

	// Log-Level auf Debug setzen
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting reverse proxy with rotating log file in: %s", *logDir)
	// Lokale IP-Adressen ausgeben
	log.Println("Lokale IP-Adressen:")
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				log.Printf("Lokale IP-Adresse: %s", ipnet.IP.String())
			}
		}
	}

	// Log-Ausgabe mit Konfigurationsdetails
	log.Printf("Starting reverse proxy - listening on port %s, forwarding to https://%s/\n", *listenPort, *targetIP)

	// TOFU Transport konfigurieren
	tofuTransport := createTOFUTransport(*targetIP, *certDir)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			targetURL, _ := url.Parse(fmt.Sprintf("https://%s/", *targetIP))
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			// Optional: Pfad anpassen, falls nötig
			log.Printf("Proxy-Director: forwarding to %s", req.URL.String())
		},
		ModifyResponse: func(pr *http.Response) error {
			setCookie := pr.Header.Get("Set-Cookie")
			if setCookie != "" {
				log.Println("Allowing Session Cookie to be served over insecure connection")
				newSetCookie := strings.Replace(setCookie, ";secure", "", -1)
				pr.Header.Set("Set-Cookie", newSetCookie)
			}
			return nil
		},
		Transport: tofuTransport,
	}

	http.Handle("/", &ProxyHandler{proxy})
	err = http.ListenAndServe(":"+*listenPort, nil)
	if err != nil {
		panic(err)
	}
}

type ProxyHandler struct {
	p *httputil.ReverseProxy
}

func (proxyHandler *ProxyHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	// Request-URL und Body loggen
	log.Printf("Proxying request: %s %s", request.Method, request.URL.String())
	if request.Body != nil {
		bodyBytes, err := io.ReadAll(request.Body)
		if err != nil {
			log.Printf("Fehler beim Lesen des Request-Body: %v", err)
		} else {
			log.Printf("RemoteAddr: %s %s", request.Method, request.RemoteAddr)
			log.Printf("Headers: %v", request.Header)
			log.Printf("Request-Body: %s", string(bodyBytes))
			// Body für den nächsten Handler wiederherstellen
			request.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}
	}

	// Anfrage an den Reverse-Proxy weiterleiten
	proxyHandler.p.ServeHTTP(responseWriter, request)
}

// RotatingFileWriter ist ein Writer, der alle 24 Stunden eine neue Log-Datei erstellt
type RotatingFileWriter struct {
	mutex       sync.Mutex
	dir         string
	filename    string
	file        *os.File
	createdTime time.Time
}

// NewRotatingFileWriter erstellt einen neuen Writer mit 24-Stunden-Rotation
func NewRotatingFileWriter(dir, filename string) (*RotatingFileWriter, error) {
	w := &RotatingFileWriter{
		dir:      dir,
		filename: filename,
	}

	if err := w.rotate(); err != nil {
		return nil, err
	}

	return w, nil
}

// Write implementiert das io.Writer Interface
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Überprüfen, ob eine Rotation notwendig ist (24 Stunden seit Erstellung)
	if time.Since(w.createdTime) >= 24*time.Hour {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	return w.file.Write(p)
}

// DumpTransport ist ein Transport für HTTP-Requests, der Anfragen und Antworten ausgibt
type DumpTransport struct {
	r http.RoundTripper
}

// RoundTrip implementiert das http.RoundTripper Interface
func (d *DumpTransport) RoundTrip(h *http.Request) (*http.Response, error) {
	dump, _ := httputil.DumpRequestOut(h, true)
	fmt.Printf("****REQUEST****\n%s\n", dump)
	resp, err := d.r.RoundTrip(h)
	dump, _ = httputil.DumpResponse(resp, true)
	fmt.Printf("****RESPONSE****\n%s\n****************\n\n", dump)
	return resp, err
}

// rotate erstellt eine neue Log-Datei und schließt die alte
func (w *RotatingFileWriter) rotate() error {
	// Wenn es bereits eine Datei gibt, schließe sie
	if w.file != nil {
		w.file.Close()
	}

	// Neuen Dateinamen mit Zeitstempel erstellen
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	fullPath := filepath.Join(w.dir, fmt.Sprintf("%s_%s", timestamp, w.filename))

	// Datei öffnen oder erstellen
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("fehler beim öffnen der log-datei: %v", err)
	}

	w.file = file
	w.createdTime = time.Now()

	// Alte Log-Dateien aufräumen (älter als 3 Tage)
	go w.cleanupOldLogs()

	return nil
}

// cleanupOldLogs entfernt Log-Dateien, die älter als 3 Tage sind
func (w *RotatingFileWriter) cleanupOldLogs() {
	files, err := os.ReadDir(w.dir)
	if err != nil {
		log.Printf("Fehler beim Lesen des Log-Verzeichnisses: %v", err)
		return
	}

	// Datum von vor 3 Tagen
	cutoffTime := time.Now().Add(-72 * time.Hour)

	for _, file := range files {
		if !file.IsDir() && strings.Contains(file.Name(), w.filename) {
			// Versuche, das Datum aus dem Dateinamen zu extrahieren
			parts := strings.Split(file.Name(), "_")
			if len(parts) < 3 {
				continue
			}

			dateStr := parts[0] + "_" + parts[1]
			fileTime, err := time.Parse("2006-01-02_15-04-05", dateStr)
			if err != nil {
				continue
			}

			if fileTime.Before(cutoffTime) {
				// Datei ist älter als 3 Tage, löschen
				fullPath := filepath.Join(w.dir, file.Name())
				if err := os.Remove(fullPath); err != nil {
					log.Printf("Fehler beim Löschen der alten Log-Datei %s: %v", fullPath, err)
				} else {
					log.Printf("Alte Log-Datei gelöscht: %s", fullPath)
				}
			}
		}
	}
}

// CertInfo speichert Informationen über ein Zertifikat
type CertInfo struct {
	Fingerprint string   `json:"fingerprint"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DNSNames    []string `json:"dns_names"`
}

// Stellt sicher, dass das angegebene Verzeichnis existiert
func ensureDirectory(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Printf("Erstelle Zertifikatsverzeichnis: %s", dir)
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			log.Fatalf("Fehler beim Erstellen des Zertifikatsverzeichnisses: %v", err)
		}
	}
}

// Speichert ein Zertifikat für eine bestimmte Host-Adresse
func saveCertificate(certDir, host string, cert *x509.Certificate) error {
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintStr := fmt.Sprintf("%x", fingerprint)

	certInfo := CertInfo{
		Fingerprint: fingerprintStr,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore.String(),
		NotAfter:    cert.NotAfter.String(),
		DNSNames:    cert.DNSNames,
	}

	jsonData, err := json.MarshalIndent(certInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("fehler beim serialisieren der zertifikatsinformationen: %v", err)
	}

	certFilePath := filepath.Join(certDir, host+".json")
	err = os.WriteFile(certFilePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("Fehler beim Speichern der Zertifikatsinformationen: %v", err)
	}

	log.Printf("Zertifikat für %s gespeichert (Fingerprint: %s)", host, fingerprintStr)
	return nil
}

// Lädt ein gespeichertes Zertifikat für eine bestimmte Host-Adresse
func loadCertificate(certDir, host string) (*CertInfo, error) {
	certFilePath := filepath.Join(certDir, host+".json")

	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		return nil, nil // Kein Zertifikat gefunden
	}

	jsonData, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Lesen der Zertifikatsdatei: %v", err)
	}

	var certInfo CertInfo
	err = json.Unmarshal(jsonData, &certInfo)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Deserialisieren der Zertifikatsinformationen: %v", err)
	}

	return &certInfo, nil
}

// Erstellt einen TLS-Transport mit TOFU (Trust On First Use) Mechanismus
func createTOFUTransport(host, certDir string) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Wir verwenden unsere eigene Validierung
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				// Konvertiert das erste Zertifikat
				if len(rawCerts) == 0 {
					return fmt.Errorf("keine Zertifikate vom Server erhalten")
				}

				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("Fehler beim Parsen des Serverzertifikats: %v", err)
				}

				// Berechne den Fingerprint des aktuellen Zertifikats
				currentFingerprint := sha256.Sum256(cert.Raw)
				currentFingerprintStr := fmt.Sprintf("%x", currentFingerprint)

				// Lade das gespeicherte Zertifikat
				savedCert, err := loadCertificate(certDir, host)
				if err != nil {
					return fmt.Errorf("Fehler beim Laden des gespeicherten Zertifikats: %v", err)
				}

				// Wenn kein Zertifikat gespeichert ist, speichere das aktuelle Zertifikat (Trust On First Use)
				if savedCert == nil {
					log.Printf("Erstes Zertifikat für %s wird gespeichert (TOFU)", host)
					return saveCertificate(certDir, host, cert)
				}

				// Vergleiche mit dem gespeicherten Fingerprint
				if savedCert.Fingerprint != currentFingerprintStr {
					log.Printf("WARNUNG: Zertifikat für %s hat sich geändert!", host)
					log.Printf("Gespeicherter Fingerprint: %s", savedCert.Fingerprint)
					log.Printf("Aktueller Fingerprint: %s", currentFingerprintStr)
					return fmt.Errorf("Zertifikat hat sich geändert! Möglicher man-in-the-middle-Angriff oder Zertifikat wurde erneuert")
				}

				log.Printf("Zertifikats-Validierung erfolgreich für %s", host)
				return nil
			},
		},
	}
}
