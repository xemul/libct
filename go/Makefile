all: run
libct.pb.go: libct.proto
	protoc --go_out=. libct.proto -I .
run:  libct.go libct.pb.go
	go test -v libct.go libct_test.go libct.pb.go
