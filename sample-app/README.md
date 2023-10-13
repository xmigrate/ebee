# filegone app
A sample, small app which could be used to help understand how to start working with cilium eBPF framework

## Files and folders

1. We have headers folder which includes the vmlinux.h and other bpf related helper functions and macros
2. filegone.c, where we write the eBPF intructions in C
3. main.go, where we have instructions to generate the eBPF bytecode, go file and the instructions for the application logic
4. bpf_bpfel_x86.go, generated file which contains functions and objects to control and read data from the eBPF code loaded to the kernel
5. bpf_bpfel_x86.o, generated eBPF object which contains the bpf bytecode for x86 architecture

## Generate the eBPF artefacts  
Execute `go generate main.go` you would be able to generate the eBPF bytecode and go file containing the functions and objects to load and control the eBPF in runtime.

## Run the app
Execute `go run *.go`. This will start the application and can be stopped by pressing `Ctrl and c` together.