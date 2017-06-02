/*-
 * Copyright (C) 2017, Vi Grey
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

package main

import (
  "github.com/tstranex/u2f"
  "github.com/gorilla/mux"
  "crypto/tls"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "net/http"
  "strings"
  "time"
)

var (
  indexContent, _ = Asset("static/index.html")
  loginContent, _ = Asset("static/login.html")
  profileContent, _ = Asset("static/profile.html")
  openSansWoffContent, _ = Asset("static/fonts/Open-Sans-regular.woff")
  layoutCSSContent, _ = Asset("static/css/layout.css")
  circleProgressJSContent, _ = Asset("static/js/circle-progress.min.js")
  jqueryJSContent, _ = Asset("static/js/jquery.min.js")
  jqueryUIJSContent, _ = Asset("static/js/jquery-ui.min.js")
  scriptsJSContent, _ = Asset("static/js/scripts.js")
  u2fApiJSContent, _ = Asset("static/js/u2f-api.js")
  faviconContent, _ = Asset("static/layout/favicon.png")
  closeSVGContent, _ = Asset("static/images/close.svg")
  failureSVGContent, _ = Asset("static/images/failure.svg")
  profileSVGContent, _ = Asset("static/images/profile.svg")
  successSVGContent, _ = Asset("static/images/success.svg")
  u2fTokenSVGContent, _ = Asset("static/images/u2f-token.svg")
)

type authSession struct {
  userID string
  authToken string
  timestamp time.Time
  lastLogin time.Time
}

func registerRequest(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/html")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  if authToken, _ := r.Cookie("authToken"); authToken != nil {
    for i, a := range authSessions {
      if a.authToken == authToken.Value {
        authSessions[i].timestamp = time.Now()
        for _, user := range users {
          if user.userID == a.userID {
            if c, u2fErr := u2f.NewChallenge(appID, trustedFacets); u2fErr == nil {
              req := u2f.NewWebRegisterRequest(c, user.registrations)
              u2fr := u2fReq{}
              u2fr.userID = user.userID
              u2fr.challenge = c
              u2fr.registration = true
              u2fReqs = append(u2fReqs, u2fr)
              json.NewEncoder(w).Encode(req)
              return
            }
          }
        }
      }
    }
  }
  http.NotFound(w, r)
}

func registerResponse(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/html")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  var regResp u2f.RegisterResponse
  if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
    http.NotFound(w, r)
    return
  }
  if authToken, _ := r.Cookie("authToken"); authToken != nil {
    for i, a := range authSessions {
      if a.authToken == authToken.Value {
        authSessions[i].timestamp = time.Now()
        for j, user := range users {
          if user.userID == a.userID {
            for _, req := range u2fReqs {
              if user.userID == req.userID && req.registration {
                challenge := req.challenge
                if reg, err := u2f.Register(regResp, *challenge, nil); err == nil {
                  users[j].registrations = append(users[j].registrations, *reg)
                  k := u2fKeyHandle{}
                  k.counter = 0
                  k.keyhandle = reg.KeyHandle
                  users[j].keyhandles = append(users[j].keyhandles, k)
                  break
                }
              }
            }
            w.Write([]byte("success"))
            return
          }
        }
      }
    }
  }
  http.NotFound(w, r)
}

func handleOpenSansWoff(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/font-woff")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(openSansWoffContent), "%", "%%"))
}

func handleLayoutCSS(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/css")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(layoutCSSContent), "%", "%%"))
}

func handleScriptsJS(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/javascript")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(scriptsJSContent), "%", "%%"))
}

func handleU2FApiJS(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/javascript")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(u2fApiJSContent), "%", "%%"))
}

func handleJqueryJS(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/javascript")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(jqueryJSContent), "%", "%%"))
}

func handleJqueryUIJS(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/javascript")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(jqueryUIJSContent), "%", "%%"))
}

func handleCircleProgressJS(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/javascript")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(circleProgressJSContent), "%", "%%"))
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "image/png")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(faviconContent), "%", "%%"))
}

func handleCloseSVG(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "image/svg+xml")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(closeSVGContent), "%", "%%"))
}

func handleFailureSVG(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "image/svg+xml")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(failureSVGContent), "%", "%%"))
}

func handleProfileSVG(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "image/svg+xml")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(profileSVGContent), "%", "%%"))
}

func handleSuccessSVG(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "image/svg+xml")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(successSVGContent), "%", "%%"))
}

func handleU2FTokenSVG(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "image/svg+xml")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  fmt.Fprintf(w, regExpReplace(string(u2fTokenSVGContent), "%", "%%"))
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/html")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  if authToken, _ := r.Cookie("authToken"); authToken != nil {
    for i, a := range authSessions {
      if a.authToken == authToken.Value {
        authSessions[i].timestamp = time.Now()
        for _, user := range users {
          if user.userID == a.userID {
            fmt.Fprintf(w, string(profileContent))
            return
          }
        }
      }
    }
  }
  http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request){
  w.Header().Add("Content-Type", "text/html")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  if authToken, _ := r.Cookie("authToken"); authToken != nil {
    for i, a := range authSessions {
      if a.authToken == authToken.Value {
        for {
          if locked {
            time.Sleep(1 * time.Second)
          } else {
            break
          }
        }
        locked = true
        authSessions = append(authSessions[:i], authSessions[i + 1:]...)
        locked = false
      }
    }
  }
  cookie := http.Cookie{Name: "authToken", MaxAge: -1}
  http.SetCookie(w, &cookie)
  http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/html")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  var sigResp u2f.SignResponse
  var sigChallenge string
  authToken, _ := r.Cookie("authToken")
  username := r.PostFormValue("username")
  password := r.PostFormValue("password")
  signature := r.PostFormValue("signature")
  for i, a := range authSessions {
    if authToken != nil {
      if a.authToken == authToken.Value {
        authSessions[i].timestamp = time.Now()
        http.Redirect(w, r, "/profile", http.StatusSeeOther)
        return
      }
    }
  }
  for i, user := range users {
    if len(signature) > 0 {
      if err := json.Unmarshal([]byte(signature), &sigResp); err == nil {
        for j, keyhandle := range user.keyhandles {
          s := base64.StdEncoding.EncodeToString(keyhandle.keyhandle)
          s = regExpReplace(s, "\\+", "-")
          s = regExpReplace(s, "\\/", "_")
          s = regExpReplace(s, "\\=", "")
          if s == sigResp.KeyHandle {
            for _, req := range u2fReqs {
              if user.userID == req.userID {
                for _, reg := range user.registrations {
                  fmt.Println(0)
                  challenge := req.challenge
                  if newCounter, err := reg.Authenticate(sigResp, *challenge, keyhandle.counter); err == nil {
                    k := u2fKeyHandle{}
                    k.counter = newCounter
                    k.keyhandle = reg.KeyHandle
                    users[i].keyhandles[j] = k
                    authTkn := randByteArray(32)
                    a := authSession{}
                    a.userID = user.userID
                    a.authToken = authTkn
                    a.timestamp = time.Now()
                    a.lastLogin = time.Now()
                    authSessions = append(authSessions, a)
                    cookie := http.Cookie{Name: "authToken", Value: authTkn,
                                          Path: "/",
                                          MaxAge: 0, HttpOnly: true}
                    http.SetCookie(w, &cookie)
                    http.Redirect(w, r, "/profile", http.StatusSeeOther)
                    return
                  } else {
                    panic(err)
                  }
                }
              }
            }
          }
        }
      }
      http.NotFound(w, r)
      return
    } else if strings.ToLower(user.username) == strings.ToLower(username) {
      if bcryptCompare([]byte(password), user.passwordHash) {
        if len(user.registrations) > 0 {
          c, err := u2f.NewChallenge(appID, trustedFacets)
          req := c.SignRequest(user.registrations)
          u2fr := u2fReq{}
          u2fr.userID = user.userID
          u2fr.challenge = c
          u2fr.registration = false
          u2fReqs = append(u2fReqs, u2fr)
          if err != nil {
            http.Redirect(w, r, "/", http.StatusInternalServerError)
            return
          }
          if sig, err := json.Marshal(req); err == nil {
            sigChallenge = string(sig)
          }
        } else {
          authTkn := randByteArray(32)
          a := authSession{}
          a.userID = user.userID
          a.authToken = authTkn
          a.timestamp = time.Now()
          authSessions = append(authSessions, a)
          cookie := http.Cookie{Name: "authToken", Value: authTkn,
                                Path: "/",
                                MaxAge: 0, HttpOnly: true}
          http.SetCookie(w, &cookie)
          http.Redirect(w, r, "/profile", http.StatusSeeOther)
          return
        }
      } else {
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
      }
    } else {
      http.Redirect(w, r, "/", http.StatusSeeOther)
      return
    }
  }
  fmt.Fprintf(w, regExpReplace(string(loginContent), "%C", sigChallenge))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/html")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  if authToken, _ := r.Cookie("authToken"); authToken != nil {
    for i, a := range authSessions {
      if a.authToken == authToken.Value {
        authSessions[i].timestamp = time.Now()
        for _, user := range users {
          if user.userID == a.userID {
            http.Redirect(w, r, "/profile", http.StatusSeeOther)
            return
          }
        }
      }
    }
  }
  fmt.Fprintf(w, string(indexContent))
}

func handleFlag(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text")
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
  if authToken, _ := r.Cookie("authToken"); authToken != nil {
    for i, a := range authSessions {
      if a.authToken == authToken.Value {
        authSessions[i].timestamp = time.Now()
        for _, user := range users {
          if user.userID == a.userID {
            w.Write([]byte("Successfully logged in as " + user.username + " with the authToken cookie value of " + authToken.Value))
            return
          }
        }
      }
    }
  }
  w.WriteHeader(http.StatusForbidden)
  w.Write([]byte("Access Denied"))
}

func startHTTPListen() {
  router := mux.NewRouter()
  router.HandleFunc("/", handleIndex)
  router.HandleFunc("/flag", handleFlag)
  router.HandleFunc("/login", handleLogin)
  router.HandleFunc("/logout", handleLogout)
  router.HandleFunc("/profile", handleProfile)
  router.HandleFunc("/fonts/Open-Sans-regular.woff", handleOpenSansWoff)
  router.HandleFunc("/css/layout.css", handleLayoutCSS)
  router.HandleFunc("/js/u2f-api.js", handleU2FApiJS)
  router.HandleFunc("/js/scripts.js", handleScriptsJS)
  router.HandleFunc("/js/jquery.min.js", handleJqueryJS)
  router.HandleFunc("/js/jquery-ui.min.js", handleJqueryUIJS)
  router.HandleFunc("/js/circle-progress.min.js", handleCircleProgressJS)
  router.HandleFunc("/layout/favicon.png", handleFavicon)
  router.HandleFunc("/images/close.svg", handleCloseSVG)
  router.HandleFunc("/images/failure.svg", handleFailureSVG)
  router.HandleFunc("/images/profile.svg", handleProfileSVG)
  router.HandleFunc("/images/success.svg", handleSuccessSVG)
  router.HandleFunc("/images/u2f-token.svg", handleU2FTokenSVG)
  router.HandleFunc("/registerRequest", registerRequest)
  router.HandleFunc("/registerResponse", registerResponse)
  cfg := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CurvePreferences: []tls.CurveID{tls.X25519},
    PreferServerCipherSuites: true,
    ServerName: serverAddress,
  }
  srv := &http.Server {
    Addr: listenAddress + ":" + localPort,
    Handler: router,
    TLSConfig: cfg,
    TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
    ReadTimeout: 1 * time.Minute,
    WriteTimeout: 1 * time.Minute,
  }
  if tlsCertPath != "" && tlsKeyPath != "" {
    cfg.CipherSuites = []uint16{
      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
    }
    srv.TLSConfig = cfg
    if err := srv.ListenAndServeTLS(tlsCertPath, tlsKeyPath); err != nil {
      panic(err)
    }
  } else {
    cfg.CipherSuites = []uint16{
      tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    }
    cert := generateTLSCert()
    cfg.Certificates = []tls.Certificate{cert}
    srv.TLSConfig = cfg
    if err := srv.ListenAndServeTLS("", ""); err != nil {
      panic(err)
    }
  }
}
