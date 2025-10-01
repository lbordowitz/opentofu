// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build darwin
// +build darwin

package cliconfig

// How the test should work:
// 1. Add "real" files in "known areas" in the virtual file system
//   - known places should include config dirs, as well as known files
// 2. Run LoadConfig, ensure the contents despite the presence of multiple files
// 3. Do ConfigDir-based load configurations which is, after all, what LoadConfig does as well. Ensure "merge conflicts" to emphasize precedence
// 4. Check DataDirs, which nothing currently actually tests lol.

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/davecgh/go-spew/spew"
)

// locationTest fully specifies the relevant filesystem contents and the expected config.
// The config files are automatically generated with the getFile function, which only
// generates host information, so we only compare expected and actual host field.
type locationTest struct {
	name        string
	files       []string
	directories []string
	envVars     map[string]string
	expected    map[string]*ConfigHost
}

//  - XDG config: ignore .terraformrc and .tofurc, only take config files in that directory
//  - environment variable: ignore everything except that environment variable

func TestConfigFileLocations(t *testing.T) {
	home := os.Getenv("HOME")
	xdg_dir := filepath.Join(home, ".myconfig")
	tests := []locationTest{
		{
			name:  ".tofurc only",
			files: []string{filepath.Join(home, ".tofurc")},
			expected: map[string]*ConfigHost{
				"config0.example.com": {
					Services: map[string]interface{}{
						"modules.v0": "https://config0.example.com/",
					},
				},
			},
		},
		{
			name:  ".terraformrc only",
			files: []string{filepath.Join(home, ".terraformrc")},
			expected: map[string]*ConfigHost{
				"config0.example.com": {
					Services: map[string]interface{}{
						"modules.v0": "https://config0.example.com/",
					},
				},
			},
		},
		{
			name:  ".tofurc and .terraformrc",
			files: []string{filepath.Join(home, ".terraformrc"), filepath.Join(home, ".tofurc")},
			expected: map[string]*ConfigHost{
				"config1.example.com": {
					Services: map[string]interface{}{
						"modules.v1": "https://config1.example.com/",
					},
				},
				"0and1.example.com": {
					Services: map[string]interface{}{
						"modules.v1": "https://0and1.example.com/",
					},
				},
			},
		},
		{
			name:  ".tofurc and .terraformrc",
			files: []string{filepath.Join(home, ".terraformrc"), filepath.Join(home, ".tofurc")},
			expected: map[string]*ConfigHost{
				"config1.example.com": {
					Services: map[string]interface{}{
						"modules.v1": "https://config1.example.com/",
					},
				},
				"0and1.example.com": {
					Services: map[string]interface{}{
						"modules.v1": "https://0and1.example.com/",
					},
				},
			},
		},
		{
			name:        "xdg directory, but with .tofurc and .terraformrc present",
			files:       []string{filepath.Join(home, ".terraformrc"), filepath.Join(home, ".tofurc"), filepath.Join(xdg_dir, "opentofu", "tofurc")},
			directories: []string{xdg_dir},
			envVars:     map[string]string{"XDG_CONFIG_HOME": xdg_dir},
			expected: map[string]*ConfigHost{
				"config1.example.com": {
					Services: map[string]interface{}{
						"modules.v1": "https://config1.example.com/",
					},
				},
				"0and1.example.com": {
					Services: map[string]interface{}{
						"modules.v1": "https://0and1.example.com/",
					},
				},
				"1and2.example.com": {
					Services: map[string]interface{}{
						"modules.v1": "https://1and2.example.com/",
					},
				},
			},
		},
		{
			name:        "xdg directory without .tofurc and .terraformrc present",
			files:       []string{filepath.Join(xdg_dir, "opentofu", "tofurc")},
			directories: []string{xdg_dir},
			envVars:     map[string]string{"XDG_CONFIG_HOME": xdg_dir},
			expected: map[string]*ConfigHost{
				"config0.example.com": {
					Services: map[string]interface{}{
						"modules.v0": "https://config0.example.com/",
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileSystem := fstest.MapFS{}
			n := len(test.files)
			for i, file := range test.files {
				b, err := getFile(i, n)
				if err != nil {
					t.Fatalf("failed to generate file %s: %v", file, err)
				}
				fileSystem[strings.TrimLeft(file, string(os.PathSeparator))] = &fstest.MapFile{
					Data: b,
					Mode: 0o600,
				}
			}
			for _, directory := range test.directories {
				fileSystem[directory] = &fstest.MapFile{
					Data: nil,
					Mode: fs.ModeDir | 0o755,
				}
			}
			for k, v := range test.envVars {
				t.Setenv(k, v)
			}
			actual, diags := LoadConfig(t.Context(), fileSystem)
			if diags.HasErrors() {
				t.Fatalf("no errors expected, got errors from diags")
			}
			if !reflect.DeepEqual(actual.Hosts, test.expected) {
				t.Errorf("wrong result\ngot:  %swant: %s", spew.Sdump(actual.Hosts), spew.Sdump(test.expected))
			}
		})
	}
}

func TestConfigDirLocations(t *testing.T) {
	// tests := []locationTest{
	// 	{
	// 		name: "heya",
	// 	},
	// }
	// for _, test := range tests {
	// 	t.Run(test.name, func(t *testing.T) {
	// 		fileSystem := fstest.MapFS{}
	// 		for _, file := range test.files {
	// 			p := filepath.Join(fixtureDir, file.realFilePath)
	// 			b, err := os.ReadFile(p)
	// 			if err != nil {
	// 				t.Fatalf("failed to read file at %s: %v", p, err)
	// 			}
	// 			fileSystem[file.virtualFilePath] = &fstest.MapFile{
	// 				Data: b,
	// 				Mode: 0o600,
	// 			}
	// 		}
	// 		for _, directory := range test.directories {
	// 			fileSystem[directory] = &fstest.MapFile{
	// 				Data: nil,
	// 				Mode: fs.ModeDir | 0o755,
	// 			}
	// 		}
	// 		actual, diags := LoadConfig(t.Context(), fileSystem)
	// 		if diags.HasErrors() {
	// 			t.Fatalf("no errors expected, got errors from diags")
	// 		}
	// 		if !reflect.DeepEqual(actual, test.expected) {
	// 			t.Errorf("wrong result\ngot:  %swant: %s", spew.Sdump(actual), spew.Sdump(test.expected))
	// 		}
	// 	})
	// }
}
func TestDataDirLocations(t *testing.T) {
	// tests := []locationTest{
	// 	{
	// 		name: "heya",
	// 	},
	// }
	// for _, test := range tests {
	// 	t.Run(test.name, func(t *testing.T) {
	// 		fileSystem := fstest.MapFS{}
	// 		for _, file := range test.files {
	// 			p := filepath.Join(fixtureDir, file.realFilePath)
	// 			b, err := os.ReadFile(p)
	// 			if err != nil {
	// 				t.Fatalf("failed to read file at %s: %v", p, err)
	// 			}
	// 			fileSystem[file.virtualFilePath] = &fstest.MapFile{
	// 				Data: b,
	// 				Mode: 0o600,
	// 			}
	// 		}
	// 		for _, directory := range test.directories {
	// 			fileSystem[directory] = &fstest.MapFile{
	// 				Data: nil,
	// 				Mode: fs.ModeDir | 0o755,
	// 			}
	// 		}
	// 		actual, diags := LoadConfig(t.Context(), fileSystem)
	// 		if diags.HasErrors() {
	// 			t.Fatalf("no errors expected, got errors from diags")
	// 		}
	// 		if !reflect.DeepEqual(actual, test.expected) {
	// 			t.Errorf("wrong result\ngot:  %swant: %s", spew.Sdump(actual), spew.Sdump(test.expected))
	// 		}
	// 	})
	// }
}

// func TestConfigFileConfigDir(t *testing.T) {
// 	homeDir := filepath.Join(t.TempDir(), "home")

// 	tests := []struct {
// 		name          string
// 		xdgConfigHome string
// 		files         []string
// 		testFunc      func() (string, error)
// 		expect        string
// 	}{
// 		{
// 			name:     "configFile: use home tofurc",
// 			testFunc: configFile,
// 			files:    []string{filepath.Join(homeDir, ".tofurc")},
// 			expect:   filepath.Join(homeDir, ".tofurc"),
// 		},
// 		{
// 			name:     "configFile: use home terraformrc",
// 			testFunc: configFile,
// 			files:    []string{filepath.Join(homeDir, ".terraformrc")},
// 			expect:   filepath.Join(homeDir, ".terraformrc"),
// 		},
// 		{
// 			name:     "configFile: use default fallback",
// 			testFunc: configFile,
// 			expect:   filepath.Join(homeDir, ".tofurc"),
// 		},
// 		{
// 			name:          "configFile: use XDG tofurc",
// 			testFunc:      configFile,
// 			xdgConfigHome: filepath.Join(homeDir, "xdg"),
// 			expect:        filepath.Join(homeDir, "xdg", "opentofu", "tofurc"),
// 		},
// 		{
// 			name:          "configFile: prefer home tofurc",
// 			testFunc:      configFile,
// 			xdgConfigHome: filepath.Join(homeDir, "xdg"),
// 			files:         []string{filepath.Join(homeDir, ".tofurc")},
// 			expect:        filepath.Join(homeDir, ".tofurc"),
// 		},
// 		{
// 			name:          "configFile: prefer home terraformrc",
// 			testFunc:      configFile,
// 			xdgConfigHome: filepath.Join(homeDir, "xdg"),
// 			files:         []string{filepath.Join(homeDir, ".terraformrc")},
// 			expect:        filepath.Join(homeDir, ".terraformrc"),
// 		},
// 		{
// 			name:     "configDir: use .terraform.d default",
// 			testFunc: configDir,
// 			expect:   filepath.Join(homeDir, ".terraform.d"),
// 		},
// 		{
// 			name:          "configDir: prefer .terraform.d",
// 			testFunc:      configDir,
// 			xdgConfigHome: filepath.Join(homeDir, "xdg"),
// 			files:         []string{filepath.Join(homeDir, ".terraform.d", "placeholder")},
// 			expect:        filepath.Join(homeDir, ".terraform.d"),
// 		},
// 		{
// 			name:          "configDir: use XDG value",
// 			testFunc:      configDir,
// 			xdgConfigHome: filepath.Join(homeDir, "xdg"),
// 			expect:        filepath.Join(homeDir, "xdg", "opentofu"),
// 		},
// 	}

// 	for _, test := range tests {
// 		fileSystem := afero.NewMemMapFs()
// 		t.Run(test.name, func(t *testing.T) {
// 			t.Setenv("HOME", homeDir)
// 			t.Setenv("XDG_CONFIG_HOME", test.xdgConfigHome)
// 			for _, f := range test.files {
// 				createFile(t, fileSystem, f)
// 			}

// 			file, err := test.testFunc()
// 			if err != nil {
// 				t.Fatalf("unexpected error: %v", err)
// 			}
// 			if test.expect != file {
// 				t.Fatalf("expected %q, but got %q", test.expect, file)
// 			}
// 		})
// 	}
// }

// func TestDataDirs(t *testing.T) {
// 	homeDir := filepath.Join(t.TempDir(), "home")

// 	tests := []struct {
// 		name        string
// 		xdgDataHome string
// 		expect      []string
// 	}{
// 		{
// 			name:        "use XDG data dir",
// 			xdgDataHome: filepath.Join(homeDir, "xdg"),
// 			expect: []string{
// 				filepath.Join(homeDir, ".terraform.d"),
// 				filepath.Join(homeDir, "xdg", "opentofu"),
// 			},
// 		},
// 		{
// 			name: "use default",
// 			expect: []string{
// 				filepath.Join(homeDir, ".terraform.d"),
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			t.Setenv("HOME", homeDir)
// 			t.Setenv("XDG_DATA_HOME", test.xdgDataHome)

// 			dirs, err := dataDirs()
// 			if err != nil {
// 				t.Fatalf("unexpected error: %v", err)
// 			}
// 			if !slices.Equal(test.expect, dirs) {
// 				t.Fatalf("expected %+v, but got %+v", test.expect, dirs)
// 			}
// 		})
// 	}
// }

// func createFile(t *testing.T, fileSystem afero.Fs, path string) {
// 	t.Helper()
// 	if err := fileSystem.MkdirAll(filepath.Dir(path), 0o755); err != nil {
// 		t.Fatal(err)
// 	}
// 	if err := afero.WriteFile(fileSystem, path, nil, 0o600); err != nil {
// 		t.Fatal(err)
// 	}
// 	t.Cleanup(func() { _ = fileSystem.RemoveAll(filepath.Dir(path)) })
// }
