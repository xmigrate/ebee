.PHONY: all update upgrade install_llvm install_clang install_bpftool install_go set_path source_profile

install: update upgrade install_llvm install_clang install_bpftool install_go set_path source_profile 

update:
	sudo apt update -y

upgrade:
	sudo apt upgrade -y

install_llvm:
	sudo apt install -y llvm

install_clang:
	sudo apt install -y clang

install_bpftool:
	sudo apt install -y bpftool

install_go:
	wget https://golang.org/dl/go1.20.2.linux-amd64.tar.gz
	sudo tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz

set_path:
	echo "export PATH=/usr/local/go/bin:${PATH}" | sudo tee -a $HOME/.profile

gen_vmlinux:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/headers/vmlinux.h