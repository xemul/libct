package libct

import "testing"
import "syscall"
import "os"

func TestSpawnExecv(t *testing.T) {
	s := &Session{}

	err := s.OpenLocal()
	if err != nil {
		t.Fail()
	}

	p, err := s.ProcessCreateDesc()
	if err != nil {
		t.Fail()
	}

	ct, err := s.ContainerCreate("test")
	if err != nil {
		t.Fail()
	}

	ct.SetNsMask(syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)

	_, err = ct.SpawnExecve(p, "true",
		[]string{"true"},
		[]string{"PATH=/bin:/usr/bin"})
	if err != nil {
		t.Fail()
	}
	ct.Wait()
}

func TestSpawnExecvStdout(t *testing.T) {
	s := &Session{}

	err := s.OpenLocal()
	if err != nil {
		t.Fail()
	}

	p, err := s.ProcessCreateDesc()
	if err != nil {
		t.Fail()
	}

	pr, pw, err := os.Pipe()
	ir, iw, err := os.Pipe()
	er, ew, err := os.Pipe()
	tr, tw, err := os.Pipe()

	p.Stdout = pw
	p.Stdin = ir
	p.Stderr = ew
	p.ExtraFiles = append(p.ExtraFiles, tr)

	ct, err := s.ContainerCreate("test")
	if err != nil {
		t.Fail()
	}

	_, err = ct.SpawnExecve(p, "bash",
		[]string{"sh", "-c", "echo ok; cat; cat <&3 >&2"},
		[]string{"PATH=/bin:/usr/bin"})
	if err != nil {
		t.Fail()
	}
	pw.Close()
	ir.Close()
	tr.Close()
	ew.Close()

	iw.WriteString("iok")
	iw.Close()
	tw.WriteString("good")
	tw.Close()

	data := make([]byte, 100)
	count, err := pr.Read(data)
	if count != 3 {
		t.Fail()
	}
	count, err = pr.Read(data)
	if count != 3 {
		t.Fail()
	}
	count, err = er.Read(data)
	if count != 4 {
		t.Fail()
	}
	ct.Wait()
}
