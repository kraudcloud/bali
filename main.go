package main

import (
	"compress/gzip"
	"crypto/sha512"
	"fmt"
	ik "github.com/devguardio/identity/go"
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

	var verify string
	var env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	cmd = &cobra.Command{
		Use:   "run PACKAGE.tar.gz -- [CMD]",
		Short: "run a container from a PACKAGE.tar.gz",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

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

			err = syscall.Chroot("/tmp/newroot/")
			if err != nil {
				panic(err)
			}

			err = syscall.Exec(args[1], args[1:], env)
			panic(fmt.Errorf("exec failed: %w", err))

		},
	}

	cmd.Flags().StringVarP(&verify, "verify", "i", "", "verify signature by identity")
	cmd.Flags().StringArrayVarP(&env, "env", "e", env, "set environment variables")

	rootCmd.AddCommand(cmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
