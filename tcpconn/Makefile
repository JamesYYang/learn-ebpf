all: bpf_target go_target

bpf_target: *.c
	BPF_CLANG=clang BPF_CFLAGS="-O2 -g -Wall -Werror" go generate

go_target: bpf_bpfel_x86.go
	go build -o hello-world

clean:
	rm -f bpf_bpfel_x86.* hello-world