.PHONY: all update upgrade install_llvm install_clang install_bpftool install_go install_bpftrace set_path source_profile build generate clean

install: update upgrade install_llvm install_clang install_go install_bpftrace install_bpftool set_path source_profile

update:
	sudo apt update -y || { echo "Update failed"; exit 1; }

upgrade:
	sudo apt upgrade -y || { echo "Upgrade failed"; exit 1; }

install_llvm:
	sudo apt install -y llvm || { echo "LLVM installation failed"; exit 1; }

install_clang:
	sudo apt install -y clang || { echo "Clang installation failed"; exit 1; }

install_bpftrace:
	sudo apt install -y bpftrace || { echo "bpftrace installation failed"; exit 1; }

install_go:
	wget https://golang.org/dl/go1.20.2.linux-amd64.tar.gz || { echo "Go download failed"; exit 1; }
	sudo tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz || { echo "Go extraction failed"; exit 1; }

install_bpftool:
	sudo apt install -y bpftool || { echo "bpftool installation failed, falling back to linux-tools-common"; sudo apt install -y linux-tools-common; }

set_path:
	echo "export PATH=/usr/local/go/bin/go:${PATH}" | sudo tee -a $HOME/.profile || { echo "Setting PATH failed"; exit 1; }

source_profile:
	source $HOME/.profile || { echo "Sourcing profile failed"; exit 1; }

gen_vmlinux:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/headers/vmlinux.h

# Generate eBPF Go bindings
generate:
	go generate ./cmd/rmdetect.go
	go generate ./cmd/execsnoop.go

# Build the ebee CLI application
build: generate
	go build -o ebee .

# Clean generated files
clean:
	rm -f cmd/*_bpfel_x86.go
	rm -f cmd/*_bpfel_x86.o
	rm -f ebee

# Install dependencies
deps:
	go mod tidy
	go mod download

# Run with sudo (for eBPF operations)
run-rmdetect: build
	sudo ./ebee rmdetect

run-execsnoop: build
	sudo ./ebee execsnoop

# Create new tool boilerplate
create-tool:
	@echo "Creating new eBPF tool..."
	@read -p "Enter tool name: " toolname; \
	read -p "Enter tool description: " description; \
	echo "Creating $$toolname tool..."; \
	cp docs/tools/template.md docs/tools/$$toolname.md; \
	sed -i "s/\[Tool Name\]/$$toolname/g" docs/tools/$$toolname.md; \
	sed -i "s/\[Brief Description\]/$$description/g" docs/tools/$$toolname.md; \
	sed -i "s/\[tool-name\]/$$toolname/g" docs/tools/$$toolname.md; \
	sed -i "s/\[filename\]/$$toolname/g" docs/tools/$$toolname.md; \
	echo "Created docs/tools/$$toolname.md"; \
	echo "Next steps:"; \
	echo "1. Create bpf/$$toolname.c"; \
	echo "2. Create cmd/$$toolname.go"; \
	echo "3. Update Makefile generate target"; \
	echo "4. Update cmd/root.go to add the command"; \
	echo "5. Customize docs/tools/$$toolname.md"
