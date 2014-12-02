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

	p, err :=s.ProcessCreateDesc();
	if err != nil {
		t.Fail()
	}

	ct, err := s.ContainerCreate("test")
	if err != nil {
		t.Fail()
	}

	ct.SetNsMask(syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)

	_, err = ct.SpawnExecve(p, "sleep",
		[]string{"sleep", "1"},
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

	p.Stdout = pw

	ct, err := s.ContainerCreate("test")
	if err != nil {
		t.Fail()
	}

	_, err = ct.SpawnExecve(p, "echo",
		[]string{"echo", "ok"},
		[]string{"PATH=/bin:/usr/bin"})
	if err != nil {
		t.Fail()
	}
	pw.Close()

	data := make([]byte, 100)
	count, err := pr.Read(data)
	if count != 3 {
		t.Fail()
	}
	ct.Wait()
}
