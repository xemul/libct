package libct

import "testing"
import "syscall"
import "os"

func init() {
	LogInit(os.Stderr, LOG_MSG)
}

func TestSpawnExecv(t *testing.T) {
	s := &Session{}

	err := s.OpenLocal()
	if err != nil {
		t.Fatal(err)
	}

	p, err := s.ProcessCreateDesc()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := s.ContainerCreate("test")
	if err != nil {
		t.Fatal(err)
	}

	ct.SetNsMask(syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)

	err = ct.SpawnExecve(p, "true",
		[]string{"true"},
		[]string{"PATH=/bin:/usr/bin"})
	if err != nil {
		t.Fatal(err)
	}
	ct.Wait()
}

func TestSpawnExecvStdout(t *testing.T) {
	s := &Session{}

	err := s.OpenLocal()
	if err != nil {
		t.Fatal(err)
	}

	p, err := s.ProcessCreateDesc()
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}

	if err = ct.AddController(CTL_CPU); err != nil {
		t.Fatal(err);
	}

	err = ct.SpawnExecve(p, "sh",
		[]string{"sh", "-c", "echo ok; cat; cat <&3 >&2"},
		[]string{"PATH=/bin:/usr/bin"})
	defer ct.Wait()
	pw.Close()
	ir.Close()
	tr.Close()
	ew.Close()
	defer pr.Close()
	defer iw.Close()
	defer tw.Close()
	defer er.Close()

	if err != nil {
		t.Fatal(err)
	}

	procs, err := ct.Processes()
	if err != nil {
		t.Fatal(err)
	}

	if len(procs) > 2 {
		t.Fatal(procs)
	}

	iw.WriteString("iok")
	iw.Close()
	tw.WriteString("good")
	tw.Close()

	ct.Wait()

	data := make([]byte, 100)
	count, err := pr.Read(data)
	if count != 6 {
		t.Fatal(count, string(data), data)
	}
	count, err = er.Read(data)
	if count != 4 {
		t.Fatal(count, string(data), data)
	}
}
