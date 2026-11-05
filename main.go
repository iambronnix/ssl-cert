package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

func main(){
	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{loadCertificate()},
		},
	}

	helloWlrd := func()http.Handler{
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		})
	}

    http.Handle("/",helloWlrd())

    server.ListenAndServeTLS("","")
    	
}

//first tries to load the ssl cert and key files from the disk,
// f they don't exist, it calls the generateCertificate() to generate a new self-signed certificate and save to the disk
func loadCertificate() tls.Certificate{
	cert, err := tls.LoadX509KeyPair("server.crt","server.key")
	if err != nil{
		
		if cert, err = generateCertficate(); err != nil{
			log.Fatal(err)
		}
	
		
	}
	return cert
}

func generateCertficate()(tls.Certificate, error){
	//Generate a new self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(365*24*time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	priv, err := rsa.GenerateKey(rand.Reader,2048)
	if err != nil{
		return tls.Certificate{},err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template,&template,&priv.PublicKey,priv)
	if err != nil{
		return tls.Certificate{},err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey: priv,
	}

	//Save the new certificate to disk

	err = os.WriteFile("server.crt", cert.Certificate[0],0644)
	if err != nil{
		return tls.Certificate{}, err
	}

	if err = os.WriteFile("server.key", x509.MarshalPKCS1PrivateKey(priv),0600);err != nil{
		return tls.Certificate{}, err
	}

	return tls.Certificate{}, err

}