package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall/js"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	sftpClient *sftp.Client
)

type File struct {
	Name   string `json:"name"`
	Rights string `json:"rights"`
	Size   int64  `json:"size"`
	Date   string `json:"date"`
	Type   string `json:"type"`
}

func filesToJS(files []File) []interface{} {
	var ret []interface{}
	for _, f := range files {
		ret = append(ret, map[string]interface{}{
			"name":   f.Name,
			"rights": f.Rights,
			"size":   f.Size,
			"date":   f.Date,
			"type":   f.Type,
		})
	}
	return ret
}

func initSftp(sc *ssh.Client) {
	var err error
	if sftpClient, err = sftp.NewClient(sc); err != nil {
		log.Printf("cannot init sftp: %v", err)
	}
}

func list(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 2 {
		log.Printf("list wrong args")
		return nil
	}
	go func() {
		path := args[0].String()
		logf("list: %s", path)
		files, err := sftpClient.ReadDir(path)
		if err != nil {
			log.Printf("failed to list %s: %v", path, err)
			args[1].Invoke(nil, 500)
			return
		}
		var res []File
		for _, f := range files {
			res = append(res, newFile(f))
		}
		args[1].Invoke(filesToJS(res), 200)
	}()
	return nil
}

func newFile(f os.FileInfo) File {
	t := "file"
	if f.IsDir() {
		t = "dir"
	}
	return File{
		Name:   f.Name(),
		Rights: safeMode(f.Mode()),
		Size:   f.Size(),
		Date:   f.ModTime().Format("2006-01-02 15:04:05"),
		Type:   t,
	}
}

func safeMode(m os.FileMode) string {
	const str = "d"
	var buf [32]byte // Mode is uint32.
	w := 0
	for i, c := range str {
		if m&(1<<uint(32-1-i)) != 0 {
			buf[w] = byte(c)
			w++
		}
	}
	if w == 0 {
		buf[w] = '-'
		w++
	}
	const rwx = "rwxrwxrwx"
	for i, c := range rwx {
		if m&(1<<uint(9-1-i)) != 0 {
			buf[w] = byte(c)
		} else {
			buf[w] = '-'
		}
		w++
	}
	return string(buf[:w])
}

func initFileBrowserAPI() {
	js.Global().Set("sftpListFiles", js.FuncOf(list))
	js.Global().Set("sftpRename", js.FuncOf(rename))
	js.Global().Set("sftpMove", js.FuncOf(move))
	js.Global().Set("sftpCopy", js.FuncOf(copy))
	js.Global().Set("sftpRemove", js.FuncOf(delete))
	js.Global().Set("sftpEdit", js.FuncOf(edit))
	js.Global().Set("sftpGetContent", js.FuncOf(getContent))
	js.Global().Set("sftpCreateFolder", js.FuncOf(createFolder))
	js.Global().Set("sftpChangePermission", js.FuncOf(changePerm))
	js.Global().Set("sftpUpload", js.FuncOf(upload))
	js.Global().Set("sftpDownload", js.FuncOf(download))
	js.Global().Set("sftpMultipleDownload", js.FuncOf(downloadMultiple))
}

func getwd() string {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return "nil"
	}
	wd, err := sftpClient.Getwd()
	if err != nil {
		log.Printf("failed to get wd: %v", err)
		return "/"
	}
	return wd
}

func rename(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 3 {
		log.Printf("rename wrong args")
		return nil
	}
	go func() {
		src := args[0].String()
		dst := args[1].String()
		logf("rename: %s to %s", src, dst)
		err := sftpClient.Rename(src, dst)
		if err != nil {
			log.Printf("failed to rename %s: %v", src, err)
		}
		apiResponse(args[2], err)
	}()
	return nil
}

func apiResponse(cb js.Value, err error) {
	if err == nil {
		cb.Invoke(map[string]interface{}{"success": true, "error": nil}, 200)
	} else {
		cb.Invoke(map[string]interface{}{"success": false, "error": err.Error()}, 500)
	}
}

func move(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 3 {
		log.Printf("move wrong args")
		return nil
	}
	go func() {
		src := args[0]
		dst := args[1].String()
		logf("move: %v to %s", src, dst)
		d, err := sftpClient.Lstat(dst)
		if err != nil {
			log.Printf("failed to lstat: %v", err)
		}
		isDir := d.IsDir()
		for i := 0; i < src.Length(); i++ {
			s := src.Index(i).String()
			target := dst
			if isDir {
				target = filepath.Join(target, filepath.Base(s))
			}
			err := sftpClient.Rename(s, target)
			if err != nil {
				log.Printf("failed to move name %s to %s: %v", s, target, err)
				apiResponse(args[2], err)
				return
			}
		}
		apiResponse(args[2], nil)
	}()
	return nil
}

func copy(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 3 {
		log.Printf("copy wrong args")
		return nil
	}
	go func() {
		src := args[0]
		dst := args[1].String()
		singleFilename := args[2].String()
		cb := args[3]
		if singleFilename != "" && src.Length() == 1 {
			dst = filepath.Join(dst, singleFilename)
		}
		logf("copy: %v to %s", src, dst)
		var cmd strings.Builder
		cmd.WriteString("cp ")
		for i := 0; i < src.Length(); i++ {
			s := src.Index(i).String()
			cmd.WriteString(s + " ")
		}
		cmd.WriteString(dst)
		res, err := runCmd(cmd.String())
		if err != nil {
			log.Printf("failed to copy %v to %s: %v, stderr: [%s]", src, dst, err, res)
			apiResponse(cb, err)
			return
		}
		apiResponse(cb, nil)
	}()
	return nil
}

func delete(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 2 {
		log.Printf("remove wrong args")
		return nil
	}
	go func() {
		items := args[0]
		cb := args[1]

		for i := 0; i < items.Length(); i++ {
			f := items.Index(i).String()
			log.Printf("deleting: %s", f)

			if err := recDelete(f); err != nil {
				log.Printf("failed to delete: %v", err)
				apiResponse(cb, err)
				return
			}
		}
		apiResponse(cb, nil)
	}()
	return nil
}

func recDelete(f string) error {
	fs, err := sftpClient.Lstat(f)
	if err != nil {
		return fmt.Errorf("failed to lstat %s: %v", f, err)
	}
	if fs.IsDir() {
		files, err := sftpClient.ReadDir(f)
		if err != nil {
			return fmt.Errorf("failed to ReadDir %s: %v", f, err)
		}
		for _, df := range files {
			if err := recDelete(filepath.Join(f, df.Name())); err != nil {
				return err
			}
		}
		err = sftpClient.RemoveDirectory(f)
		if err != nil {
			return fmt.Errorf("failed to RemoveDirectory %s: %v", f, err)
		}
	} else {
		err = sftpClient.Remove(f)
		if err != nil {
			return fmt.Errorf("failed to remove %s: %v", f, err)
		}
	}
	return nil
}

func edit(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 3 {
		log.Printf("edit wrong args")
		return nil
	}
	go func() {
		item := args[0].String()
		cb := args[2]

		log.Printf("editing: %s", item)
		f, err := sftpClient.OpenFile(item, os.O_RDWR|os.O_TRUNC)
		if err != nil {
			log.Printf("failed to open: %v", err)
			apiResponse(cb, err)
			return
		}
		if _, err := f.Write([]byte(args[1].String())); err != nil {
			log.Printf("failed to write: %v", err)
			apiResponse(cb, err)
			return
		}
		apiResponse(cb, nil)
	}()
	return nil
}

func getContent(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 2 {
		log.Printf("get content wrong args")
		return nil
	}
	go func() {
		item := args[0].String()
		cb := args[1]

		log.Printf("getContetn: %s", item)
		f, err := sftpClient.Open(item)
		if err != nil {
			log.Printf("failed to open: %v", err)
			cb.Invoke(nil, 400)
			return
		}
		fc, err := ioutil.ReadAll(f)
		if err != nil {
			log.Printf("failed to read: %v", err)
			cb.Invoke(nil, 400)
			return
		}
		cb.Invoke(string(fc), 200)
	}()
	return nil
}

func createFolder(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 2 {
		log.Printf("create folder wrong args")
		return nil
	}
	go func() {
		path := args[0].String()
		cb := args[1]

		log.Printf("create folder: %s", path)
		err := sftpClient.Mkdir(path)
		if err != nil {
			log.Printf("failed to create folder: %v", err)
			apiResponse(cb, err)
			return
		}
		apiResponse(cb, nil)
	}()
	return nil
}

func changePerm(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 4 {
		log.Printf("chmod wrong args")
		return nil
	}
	go func() {
		items := args[0]
		recursive := args[2].Bool()
		cb := args[3]

		permCode, err := strconv.ParseInt(args[1].String(), 8, 32)
		if err != nil {
			log.Printf("invalid permCode: %v", err)
			apiResponse(cb, err)
			return
		}

		for i := 0; i < items.Length(); i++ {
			f := items.Index(i).String()

			if err := chmod(f, uint32(permCode), recursive); err != nil {
				log.Printf("failed to chmod: %v", err)
				apiResponse(cb, err)
				return
			}
		}
		apiResponse(cb, nil)
	}()
	return nil
}

func chmod(path string, perm uint32, rec bool) error {
	log.Printf("chmod: %s - %v", path, os.FileMode(perm))
	err := sftpClient.Chmod(path, os.FileMode(perm))
	if err != nil || !rec {
		return err
	}
	fs, err := sftpClient.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to lstat %s: %v", path, err)
	}
	if !fs.IsDir() {
		return nil
	}
	files, err := sftpClient.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to ReadDir %s: %v", path, err)
	}
	for _, df := range files {
		if err := chmod(filepath.Join(path, df.Name()), perm, rec); err != nil {
			return err
		}
	}
	return nil
}

func upload(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 4 {
		log.Printf("upload wrong args")
		return nil
	}
	d := uint8Array.New(args[2])
	data := make([]byte, d.Get("byteLength").Int())
	log.Printf("files size: %d %s", len(data), d.Type())
	js.CopyBytesToGo(data, d)
	go func() {
		dst := args[0].String()
		fileName := args[1].String()
		cb := args[3]
		files, err := sftpClient.ReadDir(dst)
		if err != nil {
			log.Printf("failed to ReadDir dst: %v", err)
			apiResponse(cb, err)
			return
		}
		if !isUnique(fileName, files) {
			var nfn string
			for i := 1; i < 10000; i++ {
				nfn := fmt.Sprintf("%s.%d", fileName, i)
				if isUnique(nfn, files) {
					break
				}
			}
			if nfn == "" {
				log.Printf("cannot make file name %s unique", fileName)
				apiResponse(cb, fmt.Errorf("cannot make file name %s unique", fileName))
				return
			}
			fileName = nfn
		}
		f, err := sftpClient.Create(filepath.Join(dst, fileName))
		if err != nil {
			log.Printf("failed to create file %s: %v", filepath.Join(dst, fileName), err)
			apiResponse(cb, err)
			return
		}
		_, err = f.Write(data)
		if err != nil {
			log.Printf("failed to write file %s: %v", filepath.Join(dst, fileName), err)
			apiResponse(cb, err)
			return
		}
		f.Close()
		apiResponse(cb, nil)
	}()
	return nil
}

func isUnique(fn string, files []os.FileInfo) bool {
	for _, f := range files {
		if f.Name() == fn {
			return false
		}
	}
	return true
}

var uint8Array = js.Global().Get("Uint8Array")

func download(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 2 {
		log.Printf("download wrong args")
		return nil
	}
	go func() {
		path := args[0].String()
		cb := args[1]
		logf("download: %v", path)
		fs, err := sftpClient.Lstat(path)
		if err != nil || fs.IsDir() {
			log.Printf("failed to lstat: %v", err)
			cb.Invoke(nil, 400)
			return
		}
		f, err := sftpClient.Open(path)
		if err != nil {
			log.Printf("failed to open: %v", err)
			cb.Invoke(nil, 400)
			return
		}
		log.Printf("downloading %d bytes", fs.Size())
		buf := uint8Array.New(fs.Size())
		fc, err := ioutil.ReadAll(f)
		if err != nil {
			log.Printf("failed to read: %v", err)
			cb.Invoke(nil, 400)
			return
		}
		f.Close()
		js.CopyBytesToJS(buf, fc)
		cb.Invoke(buf, 200)
	}()
	return nil
}

// type uint8Array struct {
// 	d    []uint8
// 	last int
// }

// func (a *uint8Array) Write(b []byte) (n int, err error) {
// 	for i := range b {
// 		a.d[a.last] = uint8(b[i])
// 		a.last++
// 	}
// 	return len(b), nil
// }

func downloadMultiple(this js.Value, args []js.Value) interface{} {
	if sftpClient == nil {
		log.Printf("no sftp client")
		return nil
	}
	if len(args) < 2 {
		log.Printf("download wrong args")
		return nil
	}
	go func() {
		items := args[0]
		cb := args[1]
		buf := new(bytes.Buffer)
		w := zip.NewWriter(buf)

		for i := 0; i < items.Length(); i++ {
			s := items.Index(i).String()
			logf("downloadMultiple add: %s", s)
			f, err := sftpClient.Open(s)
			if err != nil {
				log.Printf("failed to open: %v", err)
				cb.Invoke(nil, 400)
				return
			}
			fc, err := ioutil.ReadAll(f)
			if err != nil {
				log.Printf("failed to read: %v", err)
				cb.Invoke(nil, 400)
				return
			}
			f.Close()
			zf, err := w.Create(filepath.Base(s))
			if err != nil {
				log.Printf("failed to create zip entry: %v", err)
				cb.Invoke(nil, 400)
				return
			}
			_, err = zf.Write(fc)
			if err != nil {
				log.Printf("failed to write zip entry: %v", err)
				cb.Invoke(nil, 400)
				return
			}
		}
		if err := w.Close(); err != nil {
			log.Printf("failed to close archive: %v", err)
			cb.Invoke(nil, 400)
			return
		}
		log.Printf("downloading %d bytes", buf.Len())
		jbuf := uint8Array.New(buf.Len())
		js.CopyBytesToJS(jbuf, buf.Bytes())
		cb.Invoke(jbuf, 200)
	}()
	return nil
}
