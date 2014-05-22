package libct

import "net"
import "fmt"
import "syscall"
import "sync/atomic"
import prot "code.google.com/p/goprotobuf/proto"

type Session struct {
	sk       *net.UnixConn
	resp_map map[uint64]chan *RpcResponse
}

type Container struct {
	s   *Session
	Rid uint64
	pid int32
}

type LibctError struct {
	Code int32
}

func (e LibctError) Error() string {
	return fmt.Sprintf("LibctError: %x", e.Code)
}

func OpenSession() (*Session, error) {
	addr, err := net.ResolveUnixAddr("unixpacket", "/var/run/libct.sock")
	if err != nil {
		return nil, err
	}
	sk, err := net.DialUnix("unixpacket", nil, addr)
	if err != nil {
		return nil, err
	}

	s := &Session{sk, map[uint64]chan *RpcResponse{}}

	// each request has a channel for response. All this channels are
	// collect in a map, where a key value is a request ID.
	go func() {
		for {
			resp, err := s.__recvRes()
			if err != nil {
				for _, c := range s.resp_map {
					close(c)
				}
				s.sk.Close()
				return
			}
			s.resp_map[*resp.ReqId] <- resp
			close(s.resp_map[*resp.ReqId])
			delete(s.resp_map, *resp.ReqId)
		}
	}()

	return s, nil
}

var curReqID uint64 = 100

func getRpcReq() *RpcRequest {
	req := &RpcRequest{}
	id := atomic.AddUint64(&curReqID, 1)
	req.ReqId = &id
	return req
}

// Send request to the server
func (s *Session) __sendReq(req *RpcRequest, pipes *Pipes) error {
	pkt, err := prot.Marshal(req)
	if err != nil {
		return err
	}

	var rights []byte
	if pipes != nil {
		rights = syscall.UnixRights(pipes.Stdin, pipes.Stdout, pipes.Stderr)
	} else {
		rights = nil
	}

	_, _, err = s.sk.WriteMsgUnix(pkt, rights, nil)
	if err != nil {
		return err
	}

	return nil
}

// Send request and return a channel with response
func (s *Session) sendReq(req *RpcRequest, pipes *Pipes) (chan *RpcResponse, error) {
	c := make(chan *RpcResponse, 1)
	s.resp_map[*req.ReqId] = c

	err := s.__sendReq(req, pipes)
	if err != nil {
		close(s.resp_map[*req.ReqId])
		delete(s.resp_map, *req.ReqId)
		return nil, err
	}

	return c, nil
}

// Send request and return response
func (s *Session) makeReqWithPipes(req *RpcRequest, pipes *Pipes) (*RpcResponse, error) {
	c, err := s.sendReq(req, pipes)
	if err != nil {
		return nil, err
	}

	resp := <-c

	if resp == nil {
		return nil, LibctError{-1}
	}

	if !(*resp.Success) {
		return nil, LibctError{resp.GetError()}
	}

	return resp, nil
}

func (s *Session) makeReq(req *RpcRequest) (*RpcResponse, error) {
	return s.makeReqWithPipes(req, nil)
}

// receive response from the server
func (s *Session) __recvRes() (*RpcResponse, error) {

	pkt := make([]byte, 4096)
	size, err := s.sk.Read(pkt)
	if err != nil {
		return nil, err
	}

	res := &RpcResponse{}
	err = prot.Unmarshal(pkt[0:size], res)
	if err != nil {
		return nil, err
	}

	if !res.GetSuccess() {
		return nil, LibctError{res.GetError()}
	}

	return res, nil
}

func (s *Session) CreateCt(name string) (*Container, error) {
	req := getRpcReq()

	req.Req = ReqType_CT_CREATE.Enum()

	req.Create = &CreateReq{
		Name: prot.String(name),
	}

	res, err := s.makeReq(req)
	if err != nil {
		return nil, err
	}

	return &Container{s, res.Create.GetRid(), 0}, nil
}

func (s *Session) OpenCt(name string) (*Container, error) {
	req := getRpcReq()

	req.Req = ReqType_CT_OPEN.Enum()

	req.Create = &CreateReq{
		Name: prot.String(name),
	}

	res, err := s.makeReq(req)
	if err != nil {
		return nil, err
	}

	return &Container{s, res.Create.GetRid(), 0}, nil
}

type Pipes struct {
	Stdin, Stdout, Stderr int
}

func (ct *Container) Run(path string, argv []string, env []string, pipes *Pipes) error {
	pipes_here := (pipes != nil)
	req := getRpcReq()

	req.Req = ReqType_CT_SPAWN.Enum()
	req.CtRid = &ct.Rid

	req.Execv = &ExecvReq{
		Path:  &path,
		Args:  argv,
		Env:   env,
		Pipes: &pipes_here,
	}

	_, err := ct.s.makeReqWithPipes(req, pipes)
	return err
}

func (ct *Container) Wait() error {
	req := getRpcReq()

	req.Req = ReqType_CT_WAIT.Enum()
	req.CtRid = &ct.Rid

	_, err := ct.s.makeReq(req)

	return err
}

func (ct *Container) Kill() error {
	req := getRpcReq()

	req.Req = ReqType_CT_KILL.Enum()
	req.CtRid = &ct.Rid

	_, err := ct.s.makeReq(req)

	return err
}

const (
	CT_ERROR   int = -1
	CT_STOPPED     = 0
	CT_RUNNING     = 1
)

func (ct *Container) State() (int, error) {
	req := getRpcReq()

	req.Req = ReqType_CT_GET_STATE.Enum()
	req.CtRid = &ct.Rid

	resp, err := ct.s.makeReq(req)
	if err != nil {
		return CT_ERROR, err
	}

	return int(resp.State.GetState()), nil
}

func (ct *Container) SetNsMask(nsmask uint64) error {
	req := getRpcReq()
	req.Req = ReqType_CT_SETNSMASK.Enum()
	req.CtRid = &ct.Rid
	req.Nsmask = &NsmaskReq{Mask: &nsmask}

	_, err := ct.s.makeReq(req)

	return err
}

func (ct *Container) SetFsRoot(root string) error {
	req := getRpcReq()
	req.Req = ReqType_FS_SETROOT.Enum()
	req.CtRid = &ct.Rid
	req.Setroot = &SetrootReq{Root: &root}

	_, err := ct.s.makeReq(req)

	return err
}

const (
	CT_FS_NONE   = 0
	CT_FS_SUBDIR = 1
)

func (ct *Container) SetFsPrivate(ptype int32, path string) error {
	req := getRpcReq()
	req.Req = ReqType_FS_SETPRIVATE.Enum()
	req.CtRid = &ct.Rid
	req.Setpriv = &SetprivReq{Type: &ptype, Path: &path}

	_, err := ct.s.makeReq(req)

	return err
}

func (ct *Container) AddMount(src, dst string) error {
	req := getRpcReq()
	req.Req = ReqType_FS_ADD_MOUNT.Enum()
	req.CtRid = &ct.Rid
	flags := int32(0)
	req.Mnt = &MountReq{
		Dst:   &dst,
		Src:   &src,
		Flags: &flags,
	}

	_, err := ct.s.makeReq(req)

	return err
}

func (ct *Container) SetOption(opt int32) error {
	req := getRpcReq()
	req.Req = ReqType_CT_SET_OPTION.Enum()
	req.CtRid = &ct.Rid
	req.Setopt = &SetoptionReq{Opt: &opt}

	_, err := ct.s.makeReq(req)

	return err
}
