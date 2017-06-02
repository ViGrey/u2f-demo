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
  "golang.org/x/crypto/bcrypt"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/tls"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/base64"
  "encoding/pem"
  "math/big"
  "time"
)

func crypt(pass []byte) []byte {
  hash, _ := bcrypt.GenerateFromPassword(pass, 12)
  return hash
}

func bcryptCompare(pass, hash []byte) bool {
  if err := bcrypt.CompareHashAndPassword(hash, pass); err != nil {
    return false
  }
  return true
}

func pemBlockForKey(priv *ecdsa.PrivateKey) *pem.Block {
  b, err := x509.MarshalECPrivateKey(priv)
  if err != nil {
    panic(err)
  }
  return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
}

func generateTLSCert() tls.Certificate {
  privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    panic(err)
  }
  serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
  serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
  if err != nil {
    panic("Error creating TLS Serial Number")
  }
  tlsDomain := serverAddress
  certificateTemplate := x509.Certificate{
    SerialNumber: serialNumber,
    Subject: pkix.Name{
      Organization: []string{"U2F Exploit Demo"},
    },
    NotBefore: time.Now().Add(-720 * time.Hour).UTC(),
    NotAfter: time.Now().Add(876000 * time.Hour).UTC(),
    KeyUsage: (x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature),
    IsCA: true,
    BasicConstraintsValid: true,
    DNSNames: []string{tlsDomain},
  }
  serialNumber = nil
  derBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate,
                                          &certificateTemplate,
                                          &privkey.PublicKey, privkey)
  if err != nil {
    panic("Error creating X509 Certificate")
  }
  cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
  key := pem.EncodeToMemory(pemBlockForKey(privkey))
  cer, err := tls.X509KeyPair(cert, key)
  if err != nil {
    panic("Error creating TLS Certificate")
  }
  return cer
}

// Generate a random byte array of size length
func randByteArray(size int) string {
  randValue := make([]byte, size)
  if _, err := rand.Read(randValue); err != nil {
    panic(err)
  }
  return base64.StdEncoding.EncodeToString(randValue)
}

