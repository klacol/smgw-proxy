package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
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
		Rewrite: func(pr *httputil.ProxyRequest) {
			targetURL, _ := url.Parse(fmt.Sprintf("https://%s/", *targetIP))
			pr.SetURL(targetURL)
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
	err := http.ListenAndServe(":"+*listenPort, nil)
	if err != nil {
		panic(err)
	}
}

type ProxyHandler struct {
	p *httputil.ReverseProxy
}

func (ph *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request received, proxing path %s (Method %s)\n", r.URL.Path, r.Method)
	ph.p.ServeHTTP(w, r)
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
