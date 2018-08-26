package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	texttemplate "text/template"
	"time"

	"github.com/gorilla/mux"
)

var c conf
var s sessions
var ca cert

func main() {
	var config string

	flag.StringVar(&config, "config", "tmp/conf.yaml", "Path to the config file")
	flag.Parse()

	c.getConf(config)
	c.writeRules()

	err := ca.setupCA(c.CAPrivateFile, c.CACertificateFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	r := mux.NewRouter()

	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))
	r.HandleFunc("/issued", issuedHandler)
	r.HandleFunc("/", profilesHandler)
	r.HandleFunc("/profile/{profile}", viewHandler)
	r.HandleFunc("/profile/{profile}/issue", downloadHandler)

	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)
	go func() {
		sig := <-gracefulStop
		log.Printf("caught sig: %+v", sig)
		//log.Println("Wait for 2 second to finish processing")
		//time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	srv := &http.Server{
		Handler:      r,
		Addr:         c.Listen,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  time.Second * 60,
	}
	log.Fatal(srv.ListenAndServe())
}

func issuedHandler(w http.ResponseWriter, r *http.Request) {
	type webData struct {
		Profiles  []session
		Title     string
		Brand     string
		Username  string
		LogoutURL string
		HelpURL string
	}
	wd := webData{
		Profiles:  s.Items,
		Title:     c.Banner,
		Brand:     c.Banner,
		Username:  r.Header.Get(c.FullnameHeader),
		LogoutURL: c.LogoutURL,
		HelpURL:   c.HelpURL,
	}

	tmpl := template.Must(template.ParseFiles(
		"assets/template/layout.html",
		"assets/template/issued.html"))

	err := tmpl.Execute(w, &wd)
	if err != nil {
		println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profile, _ := c.getProfile(vars["profile"])
	type webData struct {
		Profiles    []session
		Title       string
		Brand       string
		Username    string
		LogoutURL   string
		Description string
		Rules       []rule
		Routes      []route
		Roles       []string
		HelpURL string
	}

	wd := webData{
		Profiles:    s.Items,
		Title:       c.Banner,
		Brand:       c.Banner,
		Username:    r.Header.Get(c.FullnameHeader),
		LogoutURL:   c.LogoutURL,
		Description: profile.Description,
		Rules:       profile.Rules,
		Routes:      profile.Routes,
		Roles:       profile.Roles,
		HelpURL:     c.HelpURL,
	}

	tmpl := template.Must(template.ParseFiles(
		"assets/template/layout.html",
		"assets/template/rules.html"))

	err := tmpl.Execute(w, &wd)
	if err != nil {
		println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	c.markAllowedProfile(r.Header.Get(c.RolesHeader))
	vars := mux.Vars(r)
	profile, err := c.checkProfileAllowed(vars["profile"])
	if err != nil {
		http.Error(w, "Not authorized", 401)
		return
	}

	requestIP := r.RemoteAddr
	issueTime := time.Now()
	durationTime, _ := time.ParseDuration(profile.Duration)
	expireTime := issueTime.Add(durationTime)

	k, err := ca.genCertificate(issueTime, expireTime, vars["profile"])
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	mySession := session{
		IssuedOn:    issueTime.String(),
		User:        r.Header.Get(c.UsernameHeader),
		Profile:     profile.Name,
		ExpiresOn:   expireTime.String(),
		ClientIP:    requestIP,
		Hostname:    c.Host,
		Port:        c.Port,
		IssuingCA:   k.issuingCA,
		Certificate: k.publicKey,
		PrivateKey:  k.privateKey,
		Duration:    durationTime.String(),
	}

	type webData struct {
		Session session
	}
	wd := webData{
		Session: mySession,
	}

	s.AddItem(mySession)
	filename := vars["profile"] + "-" + expireTime.String() + ".ovpn"

	tmpl := texttemplate.Must(texttemplate.New(filename).Parse(c.Template))
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	err = tmpl.Execute(w, &wd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func profilesHandler(w http.ResponseWriter, r *http.Request) {
	c.markAllowedProfile(r.Header.Get(c.RolesHeader))

	type webData struct {
		Profiles  []profile
		Title     string
		Username  string
		Sessions  sessions
		Brand     string
		LogoutURL string
		HelpURL string
	}
	wd := webData{
		Profiles:  c.Profiles,
		Title:     c.Banner,
		Username:  r.Header.Get(c.FullnameHeader),
		Sessions:  s,
		Brand:     c.Banner,
		LogoutURL: c.LogoutURL,
		HelpURL: c.HelpURL,
	}

	tmpl := template.Must(template.ParseFiles(
		"assets/template/layout.html",
		"assets/template/profiles.html"))

	err := tmpl.Execute(w, &wd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
