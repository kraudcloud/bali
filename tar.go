package main

import (
	"archive/tar"
	"bufio"
	"fmt"
	"github.com/pkg/xattr"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

func untar(fo io.Reader, prefix string) error {

	t := tar.NewReader(bufio.NewReader(fo))
	for {
		hdr, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		hdr.Name = prefix + hdr.Name

		// TODO we shouldnt need this? tar is supposed to contain all a files dirs, in order, i think
		dir, _ := path.Split(hdr.Name)
		os.MkdirAll(dir, 0755)

		switch hdr.Typeflag {
		case tar.TypeLink:
			err = os.Link(prefix+hdr.Linkname, hdr.Name)
			if err != nil {
				return fmt.Errorf("Error creating link: '%s' => '%s' : %v", hdr.Name, hdr.Linkname, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			f, err := os.OpenFile(hdr.Name, os.O_RDWR|os.O_CREATE, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("Error creating file: %v", err)
			}
			if hdr.Typeflag == tar.TypeReg {
				n, err := io.Copy(f, t)
				if err != nil {
					return fmt.Errorf("Error writing file: %v", err)
				}
				f.Truncate(n)
			}
			f.Close()
		case tar.TypeSymlink:
			err = os.Symlink(hdr.Linkname, hdr.Name)
			if err != nil {
				return fmt.Errorf("Error creating symlink: %v", err)
			}
		case tar.TypeChar:
			err = syscall.Mknod(hdr.Name, syscall.S_IFCHR|uint32(hdr.Mode), int(hdr.Devmajor)<<8|int(hdr.Devminor))
			if err != nil {
				return fmt.Errorf("Error creating char device: %v", err)
			}
		case tar.TypeBlock:
			err = syscall.Mknod(hdr.Name, syscall.S_IFBLK|uint32(hdr.Mode), int(hdr.Devmajor)<<8|int(hdr.Devminor))
			if err != nil {
				return fmt.Errorf("Error creating block device: %v", err)
			}
		case tar.TypeDir:
			err = os.Mkdir(hdr.Name, os.FileMode(hdr.Mode))
			if err != nil {

				// dunno, there's a corner case where the dir was created earlier
				os.Chmod(hdr.Name, os.FileMode(hdr.Mode))

				if _, err2 := os.Stat(hdr.Name); err2 != nil {
					return fmt.Errorf("Error creating directory: %v", err)
				}
			}
		case tar.TypeFifo:
			err = syscall.Mknod(hdr.Name, syscall.S_IFIFO|uint32(hdr.Mode), 0)
			if err != nil {
				return fmt.Errorf("Error creating fifo: %v", err)
			}
		}

		os.Chtimes(hdr.Name, hdr.AccessTime, hdr.ModTime)
		os.Chown(hdr.Name, hdr.Uid, hdr.Gid)

		for key, value := range hdr.PAXRecords {
			const xattrPrefix = "SCHILY.xattr."
			if strings.HasPrefix(key, xattrPrefix) {
				xattr.Set(hdr.Name, key[len(xattrPrefix):], []byte(value))
			}
		}
	}

	return nil
}
