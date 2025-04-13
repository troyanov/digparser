package main

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// testDataCollector is a test helper function that returns list of all the
// .dig files found under testdata folder.
func testDataCollector(tb testing.TB, root string) []string {
	tb.Helper()

	var files []string

	err := filepath.WalkDir(root,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".dig") {
				files = append(files, path)
			}

			return nil
		})

	if err != nil {
		tb.Fatal("error collecting list of .dig files: ", err)
	}

	return files
}

func whitespaceNormalizer(data string) string {
	re := regexp.MustCompile(`\s+`)

	scanner := bufio.NewScanner(strings.NewReader(data))
	var result strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if line != "" {
			result.WriteString(strings.TrimSpace(re.ReplaceAllString(line, " ")) + "\n")
		} else {
			result.WriteString("\n")
		}
	}

	return result.String()
}

func TestParseDigOutput(t *testing.T) {
	files := testDataCollector(t, "testdata")

	if len(files) == 0 {
		t.Fatal("no testdata found")
	}

	for _, file := range files {
		bytes, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed reading test file %q: %v", file, err)
		}

		data := string(bytes)
		messages, err := ParseDigOutput(string(data))
		if err != nil {
			t.Error("failed parsing dig output: ", err)
		}

		// This is a poor-man validation.
		// Parsed data is converted back to a dig format and compared with the input.
		// Package miekg/dns produces dig output without a ->>HEADER<<- section,
		// hence we remove it from the original dig input before we compare.
		expected := whitespaceNormalizer(data)
		expected = strings.Trim(strings.ReplaceAll(expected, "->>HEADER<<- ", ""), "\n")

		var sb strings.Builder
		for _, m := range messages {
			sb.WriteString(whitespaceNormalizer(m.String()) + "\n")
		}

		actual := strings.Trim(sb.String(), "\n")

		if expected != actual {
			t.Errorf("Expected:\n%v\n\nActual:\n%v\n", expected, actual)
		}
	}
}
