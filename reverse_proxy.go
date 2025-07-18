package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func main() {
	// Kommandozeilenparameter definieren
	targetIP := flag.String("target", "10.11.120.2", "IP-Adresse des HAN Ports des Smart Meter Gateways")
	listenPort := flag.String("port", "8080", "Port, auf dem der SMGW-Proxy lauschen soll")
	flag.Parse()

	// Log-Level auf Debug setzen
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting reverse proxy")
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

	// myTransport := &DumpTransport{
	// 	&http.Transport{
	// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// 	},
	// }
	insecureTransport := &http.Transport{
		/*Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,*/
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//TLSHandshakeTimeout: 10 * time.Second,
	}

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
		Transport: insecureTransport,
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

func (proxyHandler *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Request-URL und Body loggen
	log.Printf("Proxying request: %s %s", r.Method, r.URL.String())
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Fehler beim Lesen des Request-Bodys: %v", err)
		} else {
			log.Printf("RemoteAddr: %s", r.RemoteAddr)
			log.Printf("Headers: %v", r.Header)
			log.Printf("Request-Body: %s", string(bodyBytes))
			// Body für den nächsten Handler wiederherstellen
			r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}
	}
	proxyHandler.p.ServeHTTP(w, r)
}

type DumpTransport struct {
	r http.RoundTripper
}

func (d *DumpTransport) RoundTrip(h *http.Request) (*http.Response, error) {
	dump, _ := httputil.DumpRequestOut(h, true)
	fmt.Printf("****REQUEST****\n%s\n", dump)
	resp, err := d.r.RoundTrip(h)
	dump, _ = httputil.DumpResponse(resp, true)
	fmt.Printf("****RESPONSE****\n%s\n****************\n\n", dump)
	return resp, err
}
