package libct

import "testing"
import "syscall"

func TestCreateCT(t *testing.T) {
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

	err = ct.SetFsPrivate(CT_FS_SUBDIR, "/home/avagin/centos")
	if err != nil {
		t.Fatal(err)
	}
	err = ct.SetFsRoot("/home/avagin/centos-root")
	if err != nil {
		t.Fatal(err)
	}

	argv := make([]string, 3)
	argv[0] = "bash"
	argv[1] = "-c"
	argv[2] = "echo Hello; sleep 1"
	env := make([]string, 0)
	err = ct.Run("/bin/bash", argv, env)
	if err != nil {
		t.Fatal(err)
	}

	// wait
	err = ct.Wait()
	if err != nil {
		t.Fatal(err)
	}
}
