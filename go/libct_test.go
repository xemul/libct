package libct

import "testing"
import "syscall"

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
		[]string{"PATH=/bin:/usr/bin"}, nil)
	if err != nil {
		t.Fail()
	}
	ct.Wait()
}
