#!/bin/bash

#
# SGX SDK
#
#python main.py "./libenclave.signed.so" 0x404b74
#python main.py "./libenclave.signed.so" 0x4033d9
#python main.py "./libenclave.signed.so" 0x401402

# sgx_ocall:
#python main.py "./libenclave.signed.so" 0x403380

#
# Rust-SGX
#
#python main.py "./enclave.signed.so" 0x4052d0
#python main.py "./enclave.signed.so" 0x4067b4

# sgx_ocall:
#python main.py "./enclave.signed.so" 0x4052d0



#
# Graphene-SGX
#

# sgx_ocall
python main.py "./libpal-Linux-SGX.so" 0x151ed

# ocall No.1
# ocall_exit
#python main.py "./libpal-Linux-SGX.so" 0x10d20

# ocall No.2
# ocall_print_string
#python main.py "./libpal-Linux-SGX.so" 0x10d40

# ocall No.3
# ocall_alloc_untrusted
#python main.py "./libpal-Linux-SGX.so" 0x10df0

# ocall No.4
# ocall_map_untrusted
#python main.py "./libpal-Linux-SGX.so" 0x10e70

# ocall No.5
# ocall_unmap_untrusted
#python main.py "./libpal-Linux-SGX.so" 0x10f10

# ocall No.6
# ocall_cpuid
#python main.py "./libpal-Linux-SGX.so" 0x10f80

# ocall No.7
# ocall_open

###python main.py "./libpal-Linux-SGX.so" 0x11010


# ocall No.8
# ocall_close
#python main.py "./libpal-Linux-SGX.so" 0x110d0



# ocall No.9
# ocall_read
###python main.py "./libpal-Linux-SGX.so" 0x11120

# ocall No.10
# ocall_write
###python main.py "./libpal-Linux-SGX.so" 0x11220

# ocall No.11
# ocall_fstat
#python main.py "./libpal-Linux-SGX.so" 0x11340

# ocall No.12
# ocall_fionread
#python main.py "./libpal-Linux-SGX.so" 0x113b0

# ocall No.13
# ocall_fsetnonblock
#python main.py "./libpal-Linux-SGX.so" 0x11400

# ocall No.14
# ocall_fchmod
#python main.py "./libpal-Linux-SGX.so" 0x11450

# ocall No.15
# ocall_fsync
#python main.py "./libpal-Linux-SGX.so" 0x114a0

# ocall No.16
# ocall_ftruncate
#python main.py "./libpal-Linux-SGX.so" 0x114f0

# ocall No.17
# ocall_mkdir
###python main.py "./libpal-Linux-SGX.so" 0x11540

# ocall No.18
# ocall_getdents
#python main.py "./libpal-Linux-SGX.so" 0x115f0

# ocall No.19
# ocall_wake_thread
#python main.py "./libpal-Linux-SGX.so" 0x116c0

# ocall No.20
# ocall_create_process
###python main.py "./libpal-Linux-SGX.so" 0x116e0

# ocall No.21
# ocall_futex
###python main.py "./libpal-Linux-SGX.so" 0x118c0

# ocall No.22
# ocall_socketpair
#python main.py "./libpal-Linux-SGX.so" 0x11960

# ocall No.23
# ocall_sock_listen
###python main.py "./libpal-Linux-SGX.so" 0x119f0

# ocall No.24
# ocall_sock_accept
#python main.py "./libpal-Linux-SGX.so" 0x11b60

# ocall No.25
# ocall_sock_connect
###python main.py "./libpal-Linux-SGX.so" 0x11ce0

# ocall No.26
# ocall_sock_recv
###python main.py "./libpal-Linux-SGX.so" 0x11ef0

# ocall No.27
# ocall_sock_send
#python main.py "./libpal-Linux-SGX.so" 0x120e0

# ocall No.28
# ocall_sock_recv_fd
###python main.py "./libpal-Linux-SGX.so" 0x12200

# ocall No.29
# ocall_sock_send_fd
###python main.py "./libpal-Linux-SGX.so" 0x123e0

# ocall No.30
# ocall_sock_setopt
###python main.py "./libpal-Linux-SGX.so" 0x12500

# ocall No.31
# ocall_sock_shutdown
#python main.py "./libpal-Linux-SGX.so" 0x125b0

# ocall No.32
# ocall_gettime
#python main.py "./libpal-Linux-SGX.so" 0x12600

# ocall No.33
# ocall_sleep
#python main.py "./libpal-Linux-SGX.so" 0x12670

# ocall No.34
# ocall_poll
###python main.py "./libpal-Linux-SGX.so" 0x12720

# ocall No.35
# ocall_rename
###python main.py "./libpal-Linux-SGX.so" 0x12850

# ocall No.36
# ocall_delete
###python main.py "./libpal-Linux-SGX.so" 0x12950

# ocall No.37
# ocall_load_debug
#python main.py "./libpal-Linux-SGX.so" 0x129f0




































