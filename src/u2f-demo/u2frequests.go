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
  "time"
)

type user struct {
  userID string
  username string
  passwordHash []byte
  registrations []u2f.Registration
  keyhandles []u2fKeyHandle
}

type u2fKeyHandle struct {
  keyhandle []byte
  counter uint32
}

type u2fReq struct {
  userID string
  challenge *u2f.Challenge
  registration bool
}

/*
 * Checks all U2F requests for any request involving keyhandle k and returns the
 * challenge and counter
 */
func checkU2FReqs(k []byte) (*u2f.Challenge, uint32) {
  for _, req := range u2fReqs {
    uID := req.userID
    c := req.challenge
    if c.Timestamp.Add(40 * time.Second).After(time.Now()) {
      for _, u := range users {
        if u.userID == uID {
          for _, u2fkeyhandle := range u.keyhandles {
            if string(u2fkeyhandle.keyhandle) == string(k) {
              return c, u2fkeyhandle.counter
            }
          }
        }
      }
    }
  }
  return nil, 0
}

// Deletes all expired U2F requests once every 10 seconds
func deleteExpiredU2FReqs() {
  for {
    for i, req := range u2fReqs {
      if req.challenge.Timestamp.Add(40 * time.Second).Before(time.Now()) {
        u2fReqs = append(u2fReqs[:i], u2fReqs[i + 1:]...)
      }
    }
    time.Sleep(10 * time.Second)
  }
}

// Deletes all expired authSessions once every 1 hour
func deleteExpiredAuthSessions() {
  for {
    for {
      if locked {
        time.Sleep(1 * time.Second)
      } else {
        break
      }
    }
    locked = true
    for i, auth := range authSessions {
      if auth.timestamp.Add(3 * time.Hour).Before(time.Now()) {
        authSessions = append(authSessions[:i], authSessions[i + 1:]...)
      }
    }
    locked = false
    time.Sleep(1 * time.Hour)
  }
}
