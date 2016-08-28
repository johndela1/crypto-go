package crypto

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

func HexToBase64(in []byte) (out string) {
	out = base64.StdEncoding.EncodeToString(in)
	return
}

func XorBytes(a, b []byte) (c []byte, err error) {
	if len(a) != len(b) {
		err = errors.New("inputs must be equal in length")
		return
	}
	c = make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return
}

func XorByte(b []byte, key byte) (result []byte) {
	result = make([]byte, len(b))
	for i := range b {
		result[i] = b[i] ^ key
	}
	return
}

func scoreText(b []byte) (score float64) {
	chars := make([]int, 26)
	for _, c := range b {
		if 'A' <= c && c <= 'Z' {
			c -= 32
		}
		if 'a' <= c && c <= 'z' {
			chars[int(c)-'a']++
		}
	}
	freqs := make([]float64, 26)
	l := len(b)
	for i, num := range chars {
		freqs[i] = float64(num) / float64(l)
		score += freqs[i]
	}
	return score
}

func break1Xor2(in []byte) (bestKey byte, bestDecoded []byte) {
	var bestScore float64
	for k := 0; k < 256; k++ {
		decoded := XorByte(in, byte(k))
		score := scoreText(decoded)
		if score > bestScore {
			bestScore = score
			bestKey = byte(k)
			bestDecoded = decoded
		}
	}
	return
}

type candidate struct {
	score   float64
	key     byte
	decoded []byte
}

func (c candidate) String() string {
	return fmt.Sprintf("%f: %q %q", c.score, c.key, string(c.decoded))
}

type ByScoreDesc []candidate

func (a ByScoreDesc) Len() int           { return len(a) }
func (a ByScoreDesc) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByScoreDesc) Less(i, j int) bool { return a[i].score > a[j].score }

func break1Xor(input []byte) (byte, []byte) {
	var cs []candidate
	inputLen := len(input)
	for i := 0; i < 256; i++ {
		key := byte(i)
		output, _ := XorBytes(
			input,
			bytes.Repeat([]byte{byte(i)}, inputLen),
		)
		score := scoreText(output)
		cs = append(cs, candidate{score, key, output})
	}
	sort.Sort(ByScoreDesc(cs))
	return cs[0].key, cs[0].decoded
}

func Crack(s *bufio.Scanner) (bestDecoded []byte) {
	var bestScore float64
	for s.Scan() {
		line := s.Text()
		bs, err := hex.DecodeString(line)
		if err != nil {
			println("error!!")
		}
		for k := 0; k < 256; k++ {
			decoded := XorByte(bs, byte(k))
			score := scoreText(decoded)
			if score > bestScore {
				bestScore = score
				bestDecoded = decoded
			}
		}
	}
	return
}
