package iam

import (
	"crypto/rand"
	"encoding/base64"
	"math"
)

func contains(arr []string, target string) bool {
	for _, str := range arr {
		if str == target {
			return true
		}
	}
	return false
}

func randomBase64String(len int) string {
	buff := make([]byte, int(math.Round(float64(len)/1.33333333333)))
	_, _ = rand.Read(buff)
	str := base64.RawURLEncoding.EncodeToString(buff)
	return str[:len]
}
