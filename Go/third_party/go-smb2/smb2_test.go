// This package is used for integration testing.

package smb2_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/medianexapp/go-smb2"
	"github.com/stretchr/testify/require"
)

func join(ss ...string) string {
	return strings.Join(ss, `\`)
}

type transportConfig struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type connConfig struct {
	RequireMessageSigning bool   `json:"signing"`
	ClientGuid            string `json:"guid"`
	SpecifiedDialect      uint16 `json:"dialect"`
}

type sessionConfig struct {
	Type        string `json:"type"`
	User        string `json:"user"`
	Password    string `json:"passwd"`
	Domain      string `json:"domain"`
	Workstation string `json:"workstation"`
	TargetSPN   string `json:"targetSPN"`
}

type treeConnConfig struct {
	Share1 string `json:"share1"`
	Share2 string `json:"share2"`
}

type config struct {
	MaxCreditBalance uint16          `json:"max_credit_balance"`
	Transport        transportConfig `json:"transport"`
	Conn             connConfig      `json:"conn,omitempty"`
	Session          sessionConfig   `json:"session,omitempty"`
	TreeConn         treeConnConfig  `json:"tree_conn"`
}

var (
	cfg     config
	fs      *smb2.Share
	fsName  string
	rfs     *smb2.Share
	rfsName string

	// services for mac ()
	sfmFS   *smb2.Share
	sfuFS   *smb2.Share
	session *smb2.Session
	dialer  *smb2.Dialer
)

func connect(f func()) {
	{
		cf, err := os.Open("client_conf.json")
		if err != nil {
			fmt.Println("cannot open client_conf.json")
			goto NO_CONNECTION
		}

		err = json.NewDecoder(cf).Decode(&cfg)
		if err != nil {
			fmt.Println("cannot decode client_conf.json")
			goto NO_CONNECTION
		}

		if cfg.Transport.Type != "tcp" {
			fmt.Println("unsupported transport type")
			goto NO_CONNECTION
		}

		if cfg.Session.Type != "ntlm" {
			panic("unsupported session type")
		}

		dialer = &smb2.Dialer{
			MaxCreditBalance: cfg.MaxCreditBalance,
			Negotiator: smb2.Negotiator{
				RequireMessageSigning: cfg.Conn.RequireMessageSigning,
				SpecifiedDialect:      cfg.Conn.SpecifiedDialect,
			},
			Initiator: &smb2.NTLMInitiator{
				User:        cfg.Session.User,
				Password:    cfg.Session.Password,
				Domain:      cfg.Session.Domain,
				Workstation: cfg.Session.Workstation,
				TargetSPN:   cfg.Session.TargetSPN,
			},
		}

		c, err := dialer.Dial(context.Background(), fmt.Sprintf("%s:%d", cfg.Transport.Host, cfg.Transport.Port))
		if err != nil {
			panic(err)
		}
		defer func() {
			_ = c.Logoff()
		}()

		fsName = cfg.TreeConn.Share1
		fs1, err := c.Mount(fsName)
		if err != nil {
			panic(err)
		}
		defer func() {
			_ = fs1.Umount()
		}()

		rfsName = cfg.TreeConn.Share2
		fs2, err := c.Mount(rfsName)
		if err != nil {
			panic(err)
		}
		defer func() {
			_ = fs2.Umount()
		}()

		sfmFS, err = c.Mount(fsName, smb2.WithMapPosix())
		if err != nil {
			panic(err)
		}
		defer func() {
			_ = sfmFS.Umount()
		}()

		sfuFS, err = c.Mount(fsName, smb2.WithMapChars())
		if err != nil {
			panic(err)
		}
		defer func() {
			_ = sfuFS.Umount()
		}()

		fs = fs1
		rfs = fs2
		session = c
	}
NO_CONNECTION:
	f()
}

func TestMain(m *testing.M) {
	var code int
	connect(func() {
		code = m.Run()
	})
	os.Exit(code)
}

func TestSFMMount(t *testing.T) {
	if sfmFS == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestSFMMount", os.Getpid())
	err := sfmFS.Mkdir(testDir, 0755)
	require.NoError(t, err)
	defer func() {
		_ = sfmFS.RemoveAll(testDir)
	}()

	reservedChars := []string{`"`, `*`, `:`, `<`, `>`, `?`, `|`, `.`, ` `}

	t.Run("files with a reserved characters", func(t *testing.T) {
		// create a file with each reserved character
		for _, rc := range reservedChars {
			data := []byte("bytes in the file" + rc)
			name := "file-" + rc
			err := sfmFS.WriteFile(join(testDir, name), data, 0644)
			require.NoError(t, err)

			// read it back
			actual, err := sfmFS.ReadFile(join(testDir, name))
			require.NoError(t, err)
			require.Equal(t, data, actual)
		}
	})

	t.Run("directories with a reserved character", func(t *testing.T) {
		// create a directory with each reserved character
		for _, rc := range reservedChars {
			name := "dir-" + rc
			// create the oddly named directory with a sub directory
			err := sfmFS.MkdirAll(join(testDir, name, "subdir"), 0755)
			require.NoError(t, err)

			// list the contents of the oddly naed directory
			f, err := sfmFS.Open(join(testDir, name))
			require.NoError(t, err)
			defer f.Close()

			infos, err := f.Readdir(-1)
			require.NoError(t, err)
			require.Len(t, infos, 1)
			require.Equal(t, "subdir", infos[0].Name())
		}
	})
}

func TestSFUMount(t *testing.T) {
	if sfuFS == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestSFUMount", os.Getpid())
	err := sfuFS.Mkdir(testDir, 0755)
	require.NoError(t, err)
	defer func() {
		_ = sfuFS.RemoveAll(testDir)
	}()

	reservedChars := []string{`*`, `?`, `:`, `>`, `<`, `|`}

	t.Run("files with a reserved characters", func(t *testing.T) {
		// create a file with each reserved character
		for _, rc := range reservedChars {
			data := []byte("bytes in the file" + rc)
			name := "file-" + rc
			err := sfuFS.WriteFile(join(testDir, name), data, 0644)
			require.NoError(t, err)

			// read it back
			actual, err := sfuFS.ReadFile(join(testDir, name))
			require.NoError(t, err)
			require.Equal(t, data, actual)
		}
	})

	t.Run("directories with a reserved character", func(t *testing.T) {
		// create a directory with each reserved character
		for _, rc := range reservedChars {
			name := "dir-" + rc
			// create the oddly named directory with a sub directory
			err := sfuFS.MkdirAll(join(testDir, name, "subdir"), 0755)
			require.NoError(t, err)

			// list the contents of the oddly naed directory
			f, err := sfuFS.Open(join(testDir, name))
			require.NoError(t, err)
			defer f.Close()

			infos, err := f.Readdir(-1)
			require.NoError(t, err)
			require.Len(t, infos, 1)
			require.Equal(t, "subdir", infos[0].Name())
		}
	})
}

func TestReaddir(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestReaddir", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	d, err := fs.Open(testDir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	fi, err := d.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(fi) != 0 {
		t.Error("unexpected content length:", len(fi))
	}

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		f.Close()
		_ = fs.Remove(testDir + `\testFile`)
	}()

	d2, err := fs.Open(testDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d2.Close()
	}()

	fi2, err := d2.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(fi2) != 1 {
		t.Error("unexpected content length:", len(fi2))
	}

	fi2, err = d2.Readdir(1)
	require.Equal(t, io.EOF, err)
	require.Empty(t, fi2)
}

func TestFile(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestFile", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		f.Close()
		_ = fs.Remove(testDir + `\testFile`)
	}()

	if f.Name() != testDir+`\testFile` {
		t.Error("unexpected name:", f.Name())
	}

	n, err := f.Write([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	if n != 4 {
		t.Error("unexpected content length:", n)
	}

	n, err = f.Write([]byte("Content"))
	if err != nil {
		t.Fatal(err)
	}

	if n != 7 {
		t.Error("unexpected content length:", n)
	}

	n64, err := f.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}

	if n64 != 0 {
		t.Error("unexpected seek length:", n64)
	}

	p := make([]byte, 10)

	n, err = f.Read(p)
	if err != nil {
		t.Fatal(err)
	}

	if n != 10 {
		t.Error("unexpected content length:", n)
	}

	if string(p) != "testConten" {
		t.Error("unexpected content:", string(p))
	}

	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	if stat.Name() != "testFile" {
		t.Error("unexpected name:", stat.Name())
	}

	if stat.Size() != 11 {
		t.Error("unexpected content length:", n)
	}

	if stat.IsDir() {
		t.Error("should be not a directory")
	}

	_ = f.Truncate(4)

	n64, err = f.Seek(-3, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}

	if n64 != 1 {
		t.Error("unexpected seek length:", n64)
	}

	n, err = f.Read(p)
	if err != nil {
		t.Fatal(err)
	}

	if n != 3 {
		t.Error("unexpected content length:", n)
	}

	if string(p[:n]) != "est" {
		t.Error("unexpected content:", string(p))
	}
}

func TestSymlink(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestSymlink", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		f.Close()
		_ = fs.Remove(testDir + `\testFile`)
	}()

	_, err = f.Write([]byte("testContent"))
	if err != nil {
		t.Fatal(err)
	}

	err = fs.Symlink(testDir+`\testFile`, testDir+`\linkToTestFile`)

	if !os.IsPermission(err) {
		if err != nil {
			t.Skip("samba doesn't support reparse point")
		}
		defer func() {
			_ = fs.Remove(testDir + `\linkToTestFile`)
		}()

		stat, err := fs.Lstat(testDir + `\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if stat.Name() != `linkToTestFile` {
			t.Error("unexpected name:", stat.Name())
		}

		if stat.Mode()&os.ModeSymlink == 0 {
			t.Error("should be a symlink")
		}

		target, err := fs.Readlink(testDir + `\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if target != testDir+`\testFile` {
			t.Error("unexpected target:", target)
		}

		f, err = fs.Open(testDir + `\linkToTestFile`)
		if err == nil { // if it supports follow-symlink
			bs, err := io.ReadAll(f)
			if err != nil {
				t.Fatal(err)
			}
			if string(bs) != "testContent" {
				t.Error("unexpected content:", string(bs))
			}
		}
	}
}

func TestIsXXX(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestIsXXX", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	f, err := fs.Create(testDir + `\Exist`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		f.Close()
		_ = fs.Remove(testDir + `\Exist`)
	}()

	_, err = fs.OpenFile(testDir+`\Exist`, os.O_CREATE|os.O_EXCL, 0666)
	if !os.IsExist(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsNotExist(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsPermission(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	_, err = fs.Open(testDir + `\notExist`)
	if os.IsExist(err) {
		t.Error("unexpected error:", err)
	}
	if !os.IsNotExist(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsPermission(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	err = fs.WriteFile(testDir+`\aaa`, []byte("aaa"), 0444)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(testDir+`\aaa`, []byte("aaa"), 0444)
	if !os.IsPermission(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	fst := fs.WithContext(ctx)
	_, err = fst.Create(testDir + `\Exist`)
	if !os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	fsc := fs.WithContext(ctx)
	_, err = fsc.Create(testDir + `\Exist`)
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}
}

func TestRename(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestRename", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	require.NoError(t, err)
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	t.Run("move", func(t *testing.T) {
		f, err := fs.Create(testDir + `\old`)
		require.NoError(t, err)
		data := []byte("testContent")
		_, err = f.Write(data)
		require.NoError(t, err)
		err = f.Close()
		require.NoError(t, err)

		err = fs.Rename(testDir+`\old`, testDir+`\new`)
		require.NoError(t, err)

		_, err = fs.Stat(testDir + `\old`)
		require.ErrorIs(t, err, os.ErrNotExist)

		f, err = fs.Open(testDir + `\new`)
		require.NoError(t, err)
		defer f.Close()
		actualData, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, data, actualData)
	})

	t.Run("move and overwrite", func(t *testing.T) {
		data := []byte("the final data")
		oldName := ".sourceFile"
		newName := "destinationFile"
		err := fs.WriteFile(join(testDir, oldName), data, 0644)
		require.NoError(t, err)

		err = fs.WriteFile(join(testDir, newName), []byte("doesn't matter"), 0644)
		require.NoError(t, err)

		err = fs.Rename(join(testDir, oldName), join(testDir, newName))
		require.NoError(t, err)

		// make sure there is no file at the old path, and that old data is in the new path
		info, err := fs.Stat(join(testDir, oldName))
		require.ErrorIs(t, err, os.ErrNotExist)
		require.Nil(t, info)

		actualData, err := fs.ReadFile(join(testDir, newName))
		require.NoError(t, err)
		require.Equal(t, data, actualData)
	})
}

func TestChtimes(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestChtimes", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		_ = fs.Remove(testDir + `\testFile`)
		t.Fatal(err)
	}

	atime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	mtime, err := time.Parse(time.RFC3339, "2006-03-08T19:32:05Z")
	if err != nil {
		t.Fatal(err)
	}

	err = fs.Chtimes(testDir+`\testFile`, atime, mtime)
	if err != nil {
		t.Fatal(err)
	}

	stat, err := fs.Stat(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}

	if !stat.ModTime().Equal(mtime) {
		t.Error("unexpected mtime:", stat.ModTime())
	}
}

func TestChmod(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestChmod", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		f.Close()
		_ = fs.Remove(testDir + `\testFile`)
	}()

	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode() != 0666 {
		t.Error("unexpected mode:", stat.Mode())
	}
	err = f.Chmod(0444)
	if err != nil {
		t.Fatal(err)
	}
	stat, err = f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode() != 0444 {
		t.Error("unexpected mode:", stat.Mode())
	}
}

func TestListSharenames(t *testing.T) {
	if session == nil {
		t.Skip()
	}
	names, err := session.ListSharenames()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	for _, expected := range []string{fsName, rfsName} {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("couldn't find share name %s in %v", expected, names)
		}
	}
}

func TestServerSideCopy(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestServerSideCopy", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	err = fs.WriteFile(join(testDir, "src.txt"), []byte("hello world!"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := fs.Open(join(testDir, "src.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()

	df, err := fs.Create(join(testDir, "dst.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer df.Close()

	_, err = io.Copy(df, sf)
	if err != nil {
		t.Error(err)
	}

	bs, err := fs.ReadFile(join(testDir, "dst.txt"))
	if err != nil {
		t.Fatal(err)
	}

	if string(bs) != "hello world!" {
		t.Error("unexpected content")
	}
}

func TestRemoveAll(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestRemoveAll", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(join(testDir, "hello.txt"), []byte("hello world!"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.Mkdir(join(testDir, "hello"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(join(testDir, "hello", "hello.txt"), []byte("hello world!"), 0444)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.RemoveAll(testDir)
	if err != nil {
		t.Error(err)
	}
}

func TestGlob(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestGlob", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	for _, dir := range []string{"", "dir1", "dir2", "dir3"} {
		if dir != "" {
			err = fs.Mkdir(join(testDir, dir), 0755)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, file := range []string{"abc.ext", "ab1.ext", "ab9.ext", "test", "tes"} {
			err = fs.WriteFile(join(testDir, dir, file), []byte("hello world!"), 0666)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	matches1, err := fs.Glob(join(testDir, "ab[0-9].ext"))
	if err != nil {
		t.Fatal(err)
	}
	expected1 := []string{join(testDir, "ab1.ext"), join(testDir, "ab9.ext")}

	if !reflect.DeepEqual(matches1, expected1) {
		t.Errorf("unexpected matches: %v != %v", matches1, expected1)
	}

	matches2, err := fs.Glob(join(testDir, "tes?"))
	if err != nil {
		t.Fatal(err)
	}
	expected2 := []string{join(testDir, "test")}

	if !reflect.DeepEqual(matches2, expected2) {
		t.Errorf("unexpected matches: %v != %v", matches2, expected2)
	}

	matches3, err := fs.Glob(join(testDir, "dir[0-2]/ab[0-9].ext"))
	if err != nil {
		t.Fatal(err)
	}
	expected3 := []string{join(testDir, "dir1", "ab1.ext"), join(testDir, "dir1", "ab9.ext"), join(testDir, "dir2", "ab1.ext"), join(testDir, "dir2", "ab9.ext")}

	if !reflect.DeepEqual(matches3, expected3) {
		t.Errorf("unexpected matches: %v != %v", matches3, expected3)
	}

	matches4, err := fs.Glob(join(testDir, "*/ab[0-9].ext"))
	if err != nil {
		t.Fatal(err)
	}
	expected4 := []string{join(testDir, "dir1", "ab1.ext"), join(testDir, "dir1", "ab9.ext"), join(testDir, "dir2", "ab1.ext"), join(testDir, "dir2", "ab9.ext"), join(testDir, "dir3", "ab1.ext"), join(testDir, "dir3", "ab9.ext")}

	if !reflect.DeepEqual(matches4, expected4) {
		t.Errorf("unexpected matches: %v != %v", matches4, expected4)
	}

	matches5, err := fs.Glob(join(testDir, "*/abcd"))
	if err != nil {
		t.Fatal(err)
	}
	expected5 := []string{}

	if !reflect.DeepEqual(matches5, expected5) {
		t.Errorf("unexpected matches: %v != %v", matches5, expected5)
	}
}

func TestEcho(t *testing.T) {
	if session == nil {
		t.Skip()
	}

	require.NoError(t, session.Echo())
}

func TestSecurityDescriptor(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestFile", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fs.RemoveAll(testDir)
	}()

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		f.Close()
		_ = fs.Remove(testDir + `\testFile`)
	}()

	flags := smb2.OwnerSecurityInformation | smb2.GroupSecurityInformation | smb2.DACLSecurityInformation
	sd, err := f.SecurityInfo(flags)
	if err != nil {
		t.Fatal(err)
	}

	if sd == nil {
		t.Error("unexpected nil SD")
	}
}
