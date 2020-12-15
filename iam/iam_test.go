package iam

import (
	"fmt"
	"testing"
)

func TestIam_New(t *testing.T) {
	iam := Iam{ClientId: "test"}
	fmt.Println(iam.ClientId)
	fmt.Println(iam.ClientSecret == "")
}
