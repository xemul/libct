package libct

import "bytes"
import "io"
import "testing"
import "syscall"
import "os"

func TestCreateCT(t *testing.T) {
	stdin, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	r, w, err := os.Pipe()
	pipes := Pipes{int(stdin.Fd()), int(w.Fd()), int(stdin.Fd())}

	s, err := OpenSession()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := s.CreateCt("test")
	if err != nil {
		t.Fatal(err)
	}

	err = ct.SetNsMask(syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	if err != nil {
		t.Fatal(err)
	}

	argv := make([]string, 3)
	argv[0] = "bash"
	argv[1] = "-c"
	argv[2] = "echo Hello; sleep 1"
	env := make([]string, 0)
	err = ct.Run("/bin/bash", argv, env, &pipes)
	if err != nil {
		t.Fatal(err)
	}

	w.Close()
	buf := new(bytes.Buffer)
	go func() {
		_, err = io.Copy(buf, r)
		r.Close()
	}()

	// wait
	err = ct.Wait()
	t.Log(buf)
	if err != nil {
		t.Fatal(err)
	}
}
