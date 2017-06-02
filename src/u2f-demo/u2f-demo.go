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

const (
  listenAddress = "localhost" //Default "localhost"
  localPort = "443" //Default "443"
  httpPort = "443" //Default "443"
  tlsCertPath = "" //Default ""
  tlsKeyPath = "" //Default ""
)

var (
  serverAddress string
  appID string
  users []user
  u2fReqs []u2fReq
  locked bool
  authSessions []authSession
  trustedFacets []string
)

func main() {
  serverAddress = "localhost" //Default "localhost"
  if httpPort != "" && httpPort != "443" {
    serverAddress += ":" + httpPort
  }
  appID = "https://" + serverAddress
  trustedFacets = append(trustedFacets, appID)
  u := user{}
  u.username = "vigrey" //Default "vigrey"
  u.passwordHash = crypt([]byte("lamepassword")) //Default crypt([]byte("lamepassword"))
  u.userID = randByteArray(32)
  users = append(users, u)
  go deleteExpiredU2FReqs()
  go deleteExpiredAuthSessions()
  startHTTPListen()
}
