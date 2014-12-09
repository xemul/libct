package libct

// #cgo CFLAGS: -DCONFIG_X86_64 -DARCH="x86" -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
// #cgo LDFLAGS: -l:libct.a -l:libnl-route-3.a -l:libnl-3.a -l:libapparmor.a -l:libselinux.a -lm
// #include "../src/include/uapi/libct.h"
// #include "../src/include/uapi/libct-errors.h"
import "C"
import "os"
import "io"
import "syscall"

type ProcessDesc struct {
	desc C.ct_process_desc_t
	handle C.ct_process_t

	// Stdin specifies the process's standard input. If Stdin is
	// nil, the process reads from the null device (os.DevNull).
	Stdin io.Reader

	// Stdout and Stderr specify the process's standard output and error.
	//
	// If either is nil, Run connects the corresponding file descriptor
	// to the null device (os.DevNull).
	//
	// If Stdout and Stderr are the same writer, at most one
	// goroutine at a time will call Write.
	Stdout io.Writer
	Stderr io.Writer

	// ExtraFiles specifies additional open files to be inherited by the
	// new process. It does not include standard input, standard output, or
	// standard error. If non-nil, entry i becomes file descriptor 3+i.
	ExtraFiles []*os.File

	childFiles      []*os.File
	closeAfterStart []io.Closer
	closeAfterWait  []io.Closer
	goroutine       []func() error
}

// interfaceEqual protects against panics from doing equality tests on
// two interfaces with non-comparable underlying types.
func interfaceEqual(a, b interface{}) bool {
	defer func() {
		recover()
	}()
	return a == b
}

func (p *ProcessDesc) writerDescriptor(w io.Writer) (f *os.File, err error) {
	if w == nil {
		f, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		p.closeAfterStart = append(p.closeAfterStart, f)
		return
	}

	if f, ok := w.(*os.File); ok {
		return f, nil
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return
	}

	p.closeAfterStart = append(p.closeAfterStart, pw)
	p.closeAfterWait = append(p.closeAfterWait, pr)
	p.goroutine = append(p.goroutine, func() error {
		_, err := io.Copy(w, pr)
		return err
	})
	return pw, nil
}

func (p *ProcessDesc) stdout() (f *os.File, err error) {
	return p.writerDescriptor(p.Stdout)
}

func (p *ProcessDesc) stderr() (f *os.File, err error) {
	if p.Stderr != nil && interfaceEqual(p.Stderr, p.Stdout) {
		return p.childFiles[1], nil
	}
	return p.writerDescriptor(p.Stderr)
}

func (c *ProcessDesc) stdin() (f *os.File, err error) {
	if c.Stdin == nil {
		f, err = os.Open(os.DevNull)
		if err != nil {
			return
		}
		c.closeAfterStart = append(c.closeAfterStart, f)
		return
	}

	if f, ok := c.Stdin.(*os.File); ok {
		return f, nil
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return
	}

	c.closeAfterStart = append(c.closeAfterStart, pr)
	c.closeAfterWait = append(c.closeAfterWait, pw)
	c.goroutine = append(c.goroutine, func() error {
		_, err := io.Copy(pw, c.Stdin)
		if err1 := pw.Close(); err == nil {
			err = err1
		}
		return err
	})
	return pr, nil
}

func (p *ProcessDesc) closeDescriptors(closers []io.Closer) {
	for _, fd := range closers {
		fd.Close()
	}
}

func (p *ProcessDesc) SetCaps(mask uint64, apply_to int) error {
	ret := C.libct_process_desc_set_caps(p.desc, C.ulong(mask), C.uint(apply_to))
	if ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) SetParentDeathSignal(sig syscall.Signal) error {
	if ret := C.libct_process_desc_set_pdeathsig(p.desc, C.int(sig)); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) SetLSMLabel(label string) error {
	if ret := C.libct_process_desc_set_lsm_label(p.desc, C.CString(label)); ret != 0 {
		return LibctError{int(ret)}
	}

	return nil
}

func (p *ProcessDesc) Wait() (int, error) {
	var status C.int

	if ret := C.libct_process_wait(p.handle, &status); ret != 0 {
		return -1, LibctError{int(ret)}
	}

	return int(status), nil
}
