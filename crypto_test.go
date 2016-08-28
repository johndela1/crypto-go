package crypto

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	ref := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	bytes, _ := hex.DecodeString(in)
	b64s := HexToBase64(bytes)
	if ref != b64s {
		t.Fail()
	}
}

func TestXorBytes(t *testing.T) {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"
	c := "746865206b696420646f6e277420706c6179"
	aBytes, _ := hex.DecodeString(a)
	bBytes, _ := hex.DecodeString(b)
	cBytes, _ := hex.DecodeString(c)
	resBytes, _ := XorBytes(aBytes, bBytes)
	if bytes.Compare(resBytes[:], cBytes[:]) != 0 {
		t.Fail()
	}

}

func TestBreak1Xor(t *testing.T) {
	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bytes, _ := hex.DecodeString(in)
	ref := "Cooking MC's like a pound of bacon"
	key, decoded := break1Xor2(bytes)
	if key != 88 {
		t.Fail()
	}
	if string(decoded) != ref {
		t.Fail()
	}
}

func TestCrack(t *testing.T) {
	f, _ := os.Open("4.txt")
	s := string(Crack(bufio.NewScanner(f)))
	if s != "Now that the party is jumping\n" {
		t.Fail()
	}
}
