package main

import (
	"compress/gzip"
	"crypto/sha512"
	"fmt"
	"github.com/containerd/cgroups/v2/cgroup2"
	ik "github.com/devguardio/identity/go"
	"github.com/dustin/go-humanize"
	"github.com/pkg/sftp"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {

	rand.Seed(time.Now().UnixNano())

	rootCmd := &cobra.Command{
		Use:   "bali",
		Short: "bali",
	}

	cmd := &cobra.Command{
		Use:   "id",
		Short: "print own signing identity",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			var vault = ik.Vault().Domain("bali")
			vault.Init(false)
			id, err := vault.Identity()
			if err != nil {
				panic(err)
			}
			fmt.Println(id)
		},
	}
	rootCmd.AddCommand(cmd)

	cmd = &cobra.Command{
		Use:   "build PACKAGE.tar.gz ...",
		Short: "build is just a wrapper for docker buildx",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

			var vault = ik.Vault().Domain("bali")
			vault.Init(false)

			of, err := os.Create(args[0])
			if err != nil {
				panic(err)
			}
			defer of.Close()

			var ofz io.WriteCloser = of

			if strings.HasSuffix(args[0], ".gz") {
				ofz = gzip.NewWriter(of)
				defer ofz.(*gzip.Writer).Close()
			}

			hash := sha512.New()

			c := exec.Command("docker", append([]string{"buildx", "build", "-o", "-"}, args[1:]...)...)
			c.Stdin = os.Stdin
			c.Stdout = io.MultiWriter(ofz, hash)
			c.Stderr = os.Stderr

			err = c.Run()
			if err != nil {
				panic(err)
			}

			sum := hash.Sum(nil)

			sig, err := vault.SignPrehashed("bali", sum[:])
			if err != nil {
				panic(err)
			}

			ofz.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})
			ofz.Write([]byte{'i', 'k', 's', 'i', 'g', 0, 0, 0})
			ofz.Write(sig[:])

			fmt.Printf("built and signed: %s\n", args[0])

		},
	}
	rootCmd.AddCommand(cmd)

	cmd = &cobra.Command{
		Use:   "verify PACKAGE.tar.gz SIGNER",
		Short: "verify signature",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			ii, err := os.Open(args[0])
			if err != nil {
				panic(err)
			}
			defer ii.Close()

			err = Verify(ii, args[1])
			if err != nil {
				panic(err)
			}

			fmt.Println("OK")

		},
	}
	rootCmd.AddCommand(cmd)

	var mem string
	var verify string
	var env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	var mounts []string

	cmd = &cobra.Command{
		Use:   "run PACKAGE.tar.gz -- [CMD]",
		Short: "run a container from a PACKAGE.tar.gz",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			exit := 0
			defer func() {
				if r := recover(); r != nil {
					panic(r)
				} else {
					os.Exit(exit)
				}
			}()

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			var cg *cgroup2.Manager

			if mem != "" {

				membytes, err := humanize.ParseBytes(mem)
				if err != nil {
					panic(fmt.Errorf("invalid memory limit: %s", err))
				}

				membytesI := int64(membytes)

				res := cgroup2.Resources{
					Memory: &cgroup2.Memory{
						Max: &membytesI,
					},
				}

				cg, err = cgroup2.NewSystemd("/", fmt.Sprintf("bali-%d.slice", os.Getpid()), -1, &res)
				if err != nil {
					panic(err)
				}

				defer func() {
					err := cg.Delete()
					if err != nil {
						panic(err)
					}
				}()
			}

			err := syscall.Unshare(syscall.CLONE_NEWNS)
			if err != nil {
				panic(err)
			}

			err = syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")
			if err != nil {
				panic(err)
			}

			err = syscall.Mount("tmpfs", "/tmp", "tmpfs", 0, "")
			if err != nil {
				panic(err)
			}

			u, err := url.Parse(args[0])
			if err != nil {
				panic(err)
			}

			var ii *os.File

			if u.Scheme == "file" || u.Scheme == "" {
				ii, err = os.Open(u.Path)
				if err != nil {
					panic(err)
				}
				defer ii.Close()
			} else if u.Scheme == "http" || u.Scheme == "https" {
				resp, err := http.Get(args[0])
				if err != nil {
					panic(err)
				}
				defer resp.Body.Close()

				ii, err = ioutil.TempFile("", "bali-download")
				if err != nil {
					panic(err)
				}
				defer os.Remove(ii.Name())

				bar := progressbar.DefaultBytes(
					resp.ContentLength,
					"downloading",
				)

				_, err = io.Copy(io.MultiWriter(ii, bar), resp.Body)
				if err != nil {
					panic(err)
				}
				ii.Close()

				ii, err = os.Open(ii.Name())
				if err != nil {
					panic(err)
				}

			} else if u.Scheme == "sftp" || u.Scheme == "scp" || u.Scheme == "ssh" {

				config := &ssh.ClientConfig{
					Auth: []ssh.AuthMethod{},

					//file is signed anyway
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}

				dirname, err := os.UserHomeDir()
				if err == nil {
					key, err := os.ReadFile(dirname + "/.ssh/id_rsa")
					if err == nil {
						signer, err := ssh.ParsePrivateKey(key)
						if err == nil {
							config.Auth = append(config.Auth, ssh.PublicKeys(signer))
						}
					}
				}

				if u.User != nil {
					config.User = u.User.Username()
					if p, ok := u.User.Password(); ok {
						config.Auth = append(config.Auth, ssh.Password(p))
					}
				} else {

					user, err := user.Current()
					if err != nil {
						panic(err)
					}
					config.User = user.Username
				}

				_, port, _ := net.SplitHostPort(u.Host)
				if port == "" {
					u.Host += ":22"
				}

				conn, err := ssh.Dial("tcp", u.Host, config)
				if err != nil {
					panic(err)
				}

				client, err := sftp.NewClient(conn)
				if err != nil {
					panic(err)
				}
				defer client.Close()

				stat, err := client.Stat(u.Path)
				if err != nil {
					panic(err)
				}

				ri, err := client.Open(u.Path)
				if err != nil {
					panic(err)
				}
				defer ri.Close()

				ii, err = ioutil.TempFile("", "bali-download")
				if err != nil {
					panic(err)
				}
				defer os.Remove(ii.Name())

				bar := progressbar.DefaultBytes(
					stat.Size(),
					"downloading",
				)

				_, err = io.Copy(io.MultiWriter(ii, bar), ri)
				if err != nil {
					panic(err)
				}
				ii.Close()

				ii, err = os.Open(ii.Name())
				if err != nil {
					panic(err)
				}

			} else {
				panic("unknown scheme " + u.Scheme)
			}

			if verify != "" {
				err = Verify(ii, verify)
				if err != nil {
					panic(err)
				}
				ii.Seek(0, 0)

				fmt.Fprintf(os.Stderr, "verified\n\n")
			}

			// peek to check if its gzip
			peek := make([]byte, 2)
			ii.Read(peek)
			ii.Seek(0, 0)

			var ir io.Reader = ii

			if peek[0] == 0x1f && peek[1] == 0x8b {
				ir, err = gzip.NewReader(ii)
				if err != nil {
					panic(err)
				}
			}

			err = os.Mkdir("/tmp/newroot", 0755)
			if err != nil {
				panic(err)
			}

			err = syscall.Mount("tmpfs", "/tmp/newroot", "tmpfs", 0, "")
			if err != nil {
				panic(err)
			}

			// copy some stuff from the host _before_ the extraction.
			// this is inconsistent with docker

			// copy /etc/resolv.conf
			err = os.Mkdir("/tmp/newroot/etc", 0755)
			if err != nil {
				panic(err)
			}

			f, err := os.Open("/etc/resolv.conf")
			if err != nil {
				panic(err)
			}

			fo, err := os.Create("/tmp/newroot/etc/resolv.conf")
			if err != nil {
				panic(err)
			}

			_, err = io.Copy(fo, f)
			if err != nil {
				panic(err)
			}

			f.Close()
			fo.Close()

			err = untar(ir, "/tmp/newroot/")
			if err != nil {
				panic(err)
			}

			os.MkdirAll("/tmp/newroot/proc", 0755)
			err = syscall.Mount("proc", "/tmp/newroot/proc", "proc", 0, "")
			if err != nil {
				panic(fmt.Errorf("mount /proc: %w", err))
			}

			os.MkdirAll("/tmp/newroot/sys", 0755)
			err = syscall.Mount("sysfs", "/tmp/newroot/sys", "sysfs", 0, "")
			if err != nil {
				panic(fmt.Errorf("mount /sys: %w", err))
			}

			os.MkdirAll("/tmp/newroot/sys/fs/cgroup", 0755)
			err = syscall.Mount("cgroup2", "/tmp/newroot/sys/fs/cgroup", "cgroup2", 0, "")
			if err != nil {
				panic(fmt.Errorf("mount /sys/fs/cgroup: %w", err))
			}

			os.MkdirAll("/tmp/newroot/dev", 0755)
			err = syscall.Mount("devtmpfs", "/tmp/newroot/dev", "devtmpfs", 0, "")
			if err != nil {
				panic(fmt.Errorf("mount /dev: %w", err))
			}

			os.MkdirAll("/tmp/newroot/dev/pts", 0755)
			err = syscall.Mount("devpts", "/tmp/newroot/dev/pts", "devpts", 0, "")
			if err != nil {
				panic(fmt.Errorf("mount /dev/pts: %w", err))
			}

			os.MkdirAll("/tmp/newroot/dev/shm", 0755)
			err = syscall.Mount("tmpfs", "/tmp/newroot/dev/shm", "tmpfs", 0, "")
			if err != nil {
				panic(fmt.Errorf("mount /dev/shm: %w", err))
			}

			os.MkdirAll("/tmp/newroot/run", 0755)
			err = syscall.Mount("tmpfs", "/tmp/newroot/run", "tmpfs", 0, "")
			if err != nil {
				panic(fmt.Errorf("mount /run: %w", err))
			}

			for _, m := range mounts {
				mm := strings.Split(m, ":")
				if len(mm) != 2 {
					panic(fmt.Errorf("invalid mount %q", m))
				}

				stat, err := os.Stat(mm[0])
				if err != nil {
					panic(err)
				}

				if stat.IsDir() {
					err = os.MkdirAll("/tmp/newroot/"+mm[1], 0755)
					if err != nil {
						panic(err)
					}

					err = syscall.Mount(mm[0], "/tmp/newroot/"+mm[1], "", syscall.MS_BIND|syscall.MS_REC, "")
					if err != nil {
						panic(fmt.Errorf("mount %q: %w", m, err))
					}
				} else {
					parent := filepath.Dir(mm[1])
					err = os.MkdirAll("/tmp/newroot/"+parent, 0755)

					f, err := os.Create("/tmp/newroot/" + mm[1])
					if err != nil {
						panic(err)
					}
					f.Close()

					err = syscall.Mount(mm[0], "/tmp/newroot/"+mm[1], "", syscall.MS_BIND, "")
					if err != nil {
						panic(fmt.Errorf("mount %q: %w", m, err))
					}
				}

			}

			for i, e := range env {
				if !strings.Contains(e, "=") {
					env[i] = e + "=" + os.Getenv(e)
				}
			}

			cc := exec.Command(args[1], args[2:]...)
			cc.Env = env
			cc.Stdin = os.Stdin
			cc.Stdout = os.Stdout
			cc.Stderr = os.Stderr
			cc.SysProcAttr = &syscall.SysProcAttr{
				Chroot: "/tmp/newroot/",
			}

			err = cc.Start()
			if err != nil {
				panic(err)
			}

			if cg != nil {
				err = cg.AddProc(uint64(cc.Process.Pid))
				if err != nil {
					panic(err)
				}
			}

			cc.Wait()

			exit = cc.ProcessState.ExitCode()
		},
	}

	cmd.Flags().StringVarP(&verify, "verify", "i", "", "verify signature by identity")
	cmd.Flags().StringArrayVarP(&env, "env", "e", env, "set environment variables")
	cmd.Flags().StringArrayVarP(&mounts, "volume", "v", mounts, "bind mount, weirdly named for docker compatibility")
	cmd.Flags().StringVarP(&mem, "mem", "m", "", "memory limit")

	rootCmd.AddCommand(cmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
