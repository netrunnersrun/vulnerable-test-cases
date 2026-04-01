package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"math/rand"
)

// Matches: go-md5-usage
func vulnerableMd5(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// Matches: go-sha1-usage
func vulnerableSha1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// Matches: go-math-rand
func vulnerableRand() int {
	return rand.Intn(1000000)
}

// Matches: go-des-cipher
func vulnerableDes(key []byte) (interface{}, error) {
	return des.NewCipher(key)
}

// Safe: use crypto/rand and SHA-256
func safeRandom() ([]byte, error) {
	b := make([]byte, 32)
	_, err := crypto_rand.Read(b)
	return b, err
}
