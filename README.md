# ebee
CLI tool for eBPF application development

## Initial setup
If you are new here and setting up the bpf environment for the first time then follow the below steps,

1. Install make

    `sudo apt install make`

2. Install the pre-requisites, clang, llvm, golang and bpftool

    `sudo make install`

3. Reload your shell to identify the go binary in the path

    `source $HOME/.profile`

4. Generate the vmlinux.h for extracting the definition of every type in the current running kernel

    `make gen_vmlinux`