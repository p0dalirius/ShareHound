package utf16le

import (
	"encoding/hex"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func TestEncodeNoneRoundtrip(t *testing.T) {
	t.Parallel()

	testData := []string{
		"a.txt",
		"",
		"a*.txt",
		"a.",
		"a ",
		"a<b",
		"a>b",
		"a|b",
		`\foo\file.txt`,
		`foo\file.txt`,
		`\foo\dir\`,
		`fizz\buzz\file.txt`,
	}

	for _, td := range testData {
		t.Run(td, func(t *testing.T) {
			encoded := Encode(td, MapCharsNone)
			decoded := Decode(encoded, MapCharsNone)
			require.Equal(t, td, decoded)
		})
	}
}

func TestEncodeSFM(t *testing.T) {
	t.Parallel()

	/**
	The expected value for most of these tests was calculated by
	1) mounting an smb share on linux with mapposix
	2) creating each of the files by either touch'ing or programmatically creating it through the samba mount
	3) then, using this library, list the created file and get the hex dump of the name string
	*/
	testData := []struct {
		scenario    string
		input       string
		expectedHex string
	}{
		{
			scenario:    "double quote",
			input:       `a"b`,
			expectedHex: "61ef80a062",
		},
		{
			scenario:    "asterisk",
			input:       `a*b`,
			expectedHex: "61ef80a162",
		},
		{
			scenario:    "colon",
			input:       "a:b",
			expectedHex: "61ef80a262",
		},
		{
			scenario:    "less than",
			input:       "a<b",
			expectedHex: "61ef80a362",
		},
		{
			scenario:    "greater than",
			input:       "a>b",
			expectedHex: "61ef80a462",
		},
		{
			scenario:    "question",
			input:       "a?b",
			expectedHex: "61ef80a562",
		},
		{
			scenario:    "pipe",
			input:       "a|b",
			expectedHex: "61ef80a762",
		},
		{
			scenario:    "ends with period",
			input:       "a.",
			expectedHex: "61ef80a9",
		},
		{
			scenario:    "end with space",
			input:       "a ",
			expectedHex: "61ef80a8",
		},
		{
			scenario:    "0x01 character",
			input:       "a" + string(rune(0x01)) + "b",
			expectedHex: "61ef808162",
		},
		{
			scenario:    "0x1f character",
			input:       "a" + string(rune(0x1f)) + "b",
			expectedHex: "61ef809f62",
		},
		{
			scenario:    "empty string",
			input:       "",
			expectedHex: "",
		},
	}

	for _, td := range testData {
		t.Run(td.scenario, func(t *testing.T) {
			t.Run("Encode", func(t *testing.T) {
				encoded := Encode(td.input, MapCharsSFM)
				u16s := make([]uint16, len(encoded)/2)
				for i := range u16s {
					u16s[i] = le.Uint16(encoded[2*i : 2*i+2])
				}
				runes := utf16.Decode(u16s)
				str := string(runes)
				require.Equal(t, td.expectedHex, hex.EncodeToString([]byte(str)))
			})

			t.Run("EncodeSlice", func(t *testing.T) {
				encoded := make([]byte, EncodedStringLen(td.input))
				written := EncodeSlice(encoded, td.input, MapCharsSFM)
				require.Equal(t, len(td.input)*2, written)
				u16s := make([]uint16, len(encoded)/2)
				for i := range u16s {
					u16s[i] = le.Uint16(encoded[2*i : 2*i+2])
				}
				runes := utf16.Decode(u16s)
				str := string(runes)
				require.Equal(t, td.expectedHex, hex.EncodeToString([]byte(str)))
			})
		})
	}
}

func TestSFMRoundtrip(t *testing.T) {
	t.Parallel()

	t.Run("reserved chars", func(t *testing.T) {
		t.Parallel()

		reservedChars := []rune{'"', '*', ':', '<', '>', '?', '|', ' ', '.'}
		for i := 1; i <= 0x1F; i++ {
			reservedChars = append(reservedChars, rune(i))
		}

		for _, c := range reservedChars {
			t.Run("char "+string(c), func(t *testing.T) {
				t.Run("single path component", func(t *testing.T) {
					in := "a" + string(c) + ".txt"
					encoded := Encode(in, MapCharsSFM)
					decoded := Decode(encoded, MapCharsSFM)
					require.Equal(t, in, decoded)
				})

				t.Run("multiple path components", func(t *testing.T) {
					t.Run("no outer slashes", func(t *testing.T) {
						in := `dir` + string(c) + `dir\foo\a` + string(c) + `.txt`
						encoded := Encode(in, MapCharsSFM)
						decoded := Decode(encoded, MapCharsSFM)
						require.Equal(t, in, decoded)
					})

					t.Run("has backslash prefix", func(t *testing.T) {
						in := `\dir` + string(c) + `dir\foo\a` + string(c) + `.txt`
						encoded := Encode(in, MapCharsSFM)
						decoded := Decode(encoded, MapCharsSFM)
						require.Equal(t, in, decoded)
					})

					t.Run("has backslash suffix", func(t *testing.T) {
						in := `dir` + string(c) + `dir\foo\a` + string(c) + `.txt\`
						encoded := Encode(in, MapCharsSFM)
						decoded := Decode(encoded, MapCharsSFM)
						require.Equal(t, in, decoded)
					})
				})
			})
		}
	})

	t.Run("period at end", func(t *testing.T) {
		t.Parallel()

		in := "file."
		encoded := Encode(in, MapCharsSFM)
		decoded := Decode(encoded, MapCharsSFM)
		require.Equal(t, in, decoded)
	})

	t.Run("space at end", func(t *testing.T) {
		t.Parallel()

		in := "file "
		encoded := Encode(in, MapCharsSFM)
		decoded := Decode(encoded, MapCharsSFM)
		require.Equal(t, in, decoded)
	})

	t.Run("empty string", func(t *testing.T) {
		t.Parallel()

		encoded := Encode("", MapCharsSFM)
		decoded := Decode(encoded, MapCharsSFM)
		require.Empty(t, decoded)
	})
}

func TestSFURoundtrip(t *testing.T) {
	t.Parallel()

	t.Run("using Encode", func(t *testing.T) {
		t.Parallel()

		t.Run("reserved characters", func(t *testing.T) {
			t.Parallel()

			reservedChars := []string{`"`, `*`, `:`, `<`, `>`, `?`, `|`, ` `, `.`}
			for _, c := range reservedChars {
				in := "a" + c + ".txt"
				encoded := Encode(in, MapCharsSFU)
				decoded := Decode(encoded, MapCharsSFU)
				require.Equal(t, in, decoded)
			}
		})

		t.Run("no reserved chars", func(t *testing.T) {
			t.Parallel()

			in := "terrible.trouble.odf"
			encoded := Encode(in, MapCharsSFU)
			decoded := Decode(encoded, MapCharsSFU)
			require.Equal(t, in, decoded)
		})

		t.Run("empty string", func(t *testing.T) {
			t.Parallel()

			encoded := Encode("", MapCharsSFU)
			decoded := Decode(encoded, MapCharsSFU)
			require.Empty(t, decoded)
		})
	})

	t.Run("using EncodeSlice", func(t *testing.T) {
		t.Parallel()

		t.Run("reserved characters", func(t *testing.T) {
			t.Parallel()

			reservedChars := []string{`"`, `*`, `:`, `<`, `>`, `?`, `|`, ` `, `.`}
			for _, c := range reservedChars {
				in := "a" + c + ".txt"
				encodedLen := EncodedStringLen(in)
				buf := make([]byte, encodedLen)
				written := EncodeSlice(buf, in, MapCharsSFU)
				require.EqualValues(t, encodedLen, written)
				decoded := Decode(buf, MapCharsSFU)
				require.Equal(t, in, decoded)
			}
		})

		t.Run("no reserved chars", func(t *testing.T) {
			t.Parallel()

			in := "going.to.dinner.mp3"
			encodedLen := EncodedStringLen(in)
			buf := make([]byte, encodedLen)
			written := EncodeSlice(buf, in, MapCharsSFU)
			require.EqualValues(t, encodedLen, written)
			decoded := Decode(buf, MapCharsSFU)
			require.Equal(t, in, decoded)
		})

		t.Run("empty string", func(t *testing.T) {
			t.Parallel()

			written := EncodeSlice(nil, "", MapCharsSFU)
			require.Zero(t, written)
		})
	})
}
