// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"os"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Direct implements subcommands.Command for the "direct" command.
type Direct struct {
	root string
	cwd  string
}

// Name implements subcommands.Command.Name.
func (*Direct) Name() string {
	return "direct"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Direct) Synopsis() string {
	return "Directly invoke the gVisor kernel (sentry) without sandboxing/namespaces."
}

// Usage implements subcommands.Command.Usage.
func (*Direct) Usage() string {
	return `direct [flags] <cmd> [args...] - runs a command.

This command directly starts the gVisor sentry in the current process, bypassing
OCI-compliant sandboxing and namespaces. It is intended for environments where
standard sandboxing is restricted, such as Android/Termux.

It automatically enables directfs and host networking.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Direct) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.root, "rootfs", "/", "path to the root filesystem")
	f.StringVar(&c.cwd, "cwd", "/", "current working directory")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*Direct) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (c *Direct) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if len(f.Args()) == 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	// Force directfs and skip-chroot for direct invocation.
	conf.DirectFS = true
	conf.SkipChroot = true
	if conf.Network != config.NetworkNone {
		conf.Network = config.NetworkHost
	}

	// Construct a minimal spec.
	spec := &specs.Spec{
		Version: specutils.Version,
		Root: &specs.Root{
			Path: c.root,
		},
		Process: &specs.Process{
			Args: f.Args(),
			Cwd:  c.cwd,
			Env:  os.Environ(),
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    []string{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
				Effective:   []string{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
				Inheritable: []string{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
				Permitted:   []string{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
			},
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{}, // No namespaces!
		},
	}

	// Standard mounts.
	spec.Mounts = []specs.Mount{
		{
			Destination: "/proc",
			Type:        "proc",
		},
		{
			Destination: "/dev",
			Type:        "tmpfs",
		},
		{
			Destination: "/sys",
			Type:        "sysfs",
			Options:     []string{"ro"},
		},
		{
			Destination: "/dev/shm",
			Type:        "tmpfs",
		},
	}

	specutils.LogSpecDebug(spec, conf.OCISeccomp)

	// Set up boot arguments.
	bootArgs := boot.Args{
		ID:    "direct-invocation",
		Spec:  spec,
		Conf:  conf,
		StdioFDs: []int{0, 1, 2},
	}

	gPlatform, err := platform.Lookup(conf.Platform)
	if err != nil {
		return util.Errorf("looking up platform: %v", err)
	}
	deviceFile, err := gPlatform.OpenDevice(conf.PlatformDevicePath)
	if err != nil {
		return util.Errorf("opening device file: %v", err)
	}
	if deviceFile != nil {
		bootArgs.Device = deviceFile
	}

	l, err := boot.New(bootArgs)
	if err != nil {
		return util.Errorf("creating loader: %v", err)
	}

	// Prepare metrics.
	metric.Initialize()

	// Direct invocation starts immediately.
	l.SetStarted()

	// Run the application and wait for it to finish.
	if err := l.Run(); err != nil {
		l.Destroy()
		return util.Errorf("running sentry: %v", err)
	}

	ws := l.WaitExit()
	log.Infof("application exiting with %+v", ws)
	*waitStatus = unix.WaitStatus(ws)

	l.Destroy()
	return subcommands.ExitSuccess
}
