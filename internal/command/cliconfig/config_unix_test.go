// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows
// +build !windows

package cliconfig

import (
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
)

func TestConfigFileConfigDir(t *testing.T) {
	homeDir := filepath.Join(t.TempDir(), "home")

	tests := []struct {
		name          string
		xdgConfigHome string
		files         []string
		expect        string
	}{
		{
			name:   "configFile: use home tofurc",
			files:  []string{filepath.Join(homeDir, ".tofurc")},
			expect: filepath.Join(homeDir, ".tofurc"),
		},
		{
			name:   "configFile: use home terraformrc",
			files:  []string{filepath.Join(homeDir, ".terraformrc")},
			expect: filepath.Join(homeDir, ".terraformrc"),
		},
		{
			name:   "configFile: use default fallback",
			expect: filepath.Join(homeDir, ".tofurc"),
		},
		{
			name:          "configFile: use XDG tofurc",
			xdgConfigHome: filepath.Join(homeDir, "xdg"),
			expect:        filepath.Join(homeDir, "xdg", "opentofu", "tofurc"),
		},
		{
			name:          "configFile: prefer home tofurc",
			xdgConfigHome: filepath.Join(homeDir, "xdg"),
			files:         []string{filepath.Join(homeDir, ".tofurc")},
			expect:        filepath.Join(homeDir, ".tofurc"),
		},
		{
			name:          "configFile: prefer home terraformrc",
			xdgConfigHome: filepath.Join(homeDir, "xdg"),
			files:         []string{filepath.Join(homeDir, ".terraformrc")},
			expect:        filepath.Join(homeDir, ".terraformrc"),
		},
		{
			name:   "configDir: use .terraform.d default",
			expect: filepath.Join(homeDir, ".terraform.d"),
		},
		{
			name:          "configDir: prefer .terraform.d",
			xdgConfigHome: filepath.Join(homeDir, "xdg"),
			files:         []string{filepath.Join(homeDir, ".terraform.d", "placeholder")},
			expect:        filepath.Join(homeDir, ".terraform.d"),
		},
		{
			name:          "configDir: use XDG value",
			xdgConfigHome: filepath.Join(homeDir, "xdg"),
			expect:        filepath.Join(homeDir, "xdg", "opentofu"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileSystem := fstest.MapFS{}
			t.Setenv("HOME", homeDir)
			t.Setenv("XDG_CONFIG_HOME", test.xdgConfigHome)
			for _, f := range test.files {
				createFile(t, fileSystem, f)
			}

			file, err := configFile(fileSystem)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.expect != file {
				t.Fatalf("expected %q, but got %q", test.expect, file)
			}
		})
	}
}

func TestDataDirs(t *testing.T) {
	homeDir := filepath.Join(t.TempDir(), "home")

	tests := []struct {
		name        string
		xdgDataHome string
		expect      []string
	}{
		{
			name:        "use XDG data dir",
			xdgDataHome: filepath.Join(homeDir, "xdg"),
			expect: []string{
				filepath.Join(homeDir, ".terraform.d"),
				filepath.Join(homeDir, "xdg", "opentofu"),
			},
		},
		{
			name: "use default",
			expect: []string{
				filepath.Join(homeDir, ".terraform.d"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileSystem := fstest.MapFS{}

			t.Setenv("HOME", homeDir)
			t.Setenv("XDG_DATA_HOME", test.xdgDataHome)

			dirs, err := dataDirs(fileSystem)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(test.expect, dirs) {
				t.Fatalf("expected %+v, but got %+v", test.expect, dirs)
			}
		})
	}
}

func createFile(t *testing.T, fileSystem fstest.MapFS, path string) {
	t.Helper()
	fileSystem[path] = &fstest.MapFile{
		Data: nil,
		Mode: 0o600,
		// Sys:  fileSystem,
	}
	// if err := fileSystem.MkdirAll(filepath.Dir(path), 0o755); err != nil {
	// 	t.Fatal(err)
	// }
	// if err := afero.WriteFile(fileSystem, path, nil, 0o600); err != nil {
	// 	t.Fatal(err)
	// }
	// t.Cleanup(func() { _ = fileSystem.RemoveAll(filepath.Dir(path)) })
}
