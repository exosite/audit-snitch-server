all: audit-snitch-server

audit/audit.pb.go: audit/audit.proto
	protoc --go_out=. audit/audit.proto

audit-snitch-server: main.go dataserver/dataserver.go httpserver/httpserver.go audit/audit.pb.go
	CGO_ENABLED=0 go build github.com/exosite/audit-snitch-server

clean:
	rm -f *~ audit/audit.pb.go audit-snitch-server

.PHONY: all clean
