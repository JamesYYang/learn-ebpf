all: bpf_target go_target

bpf_target: *.c
	BPF_CLANG=clang go generate

go_target: bpf_bpfeb.go
	go build -o hello-world

clean:
	rm -f bpf_bpfeb.* bpf_bpfel.* hello-world