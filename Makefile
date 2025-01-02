KERNEL_PATH := /home/jareste/ft_linux/linux-6.12.6
SRC := srcs/syscall.c
SRC_FORK := srcs/ft_fork.c
SRC_KILL := srcs/ft_kill.c
SRC_WAIT := srcs/ft_wait.c
SRC_MMAP := srcs/ft_mmap.c


all: add_syscall build_kernel

add_all: add_syscall add_fork add_kill add_mmap add_wait build_kernel

add_syscall:
	@echo "Adding syscall..."
	@if grep -q "548[[:space:]]\+common[[:space:]]\+get_pid_info" $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; then \
		echo "Syscall 548 already exists for get_pid_info. Continuing..."; \
	else \
		echo "548    common    get_pid_info    sys_get_pid_info" >> $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; \
	fi
	@if ! grep -q "sys_get_pid_info.o" $(KERNEL_PATH)/kernel/Makefile; then \
		echo "obj-y += sys_get_pid_info.o" >> $(KERNEL_PATH)/kernel/Makefile; \
	fi
	@cp -f $(SRC) $(KERNEL_PATH)/kernel/sys_get_pid_info.c
	@echo "Syscall added or confirmed successfully."

add_fork:
	@echo "Adding fork..."
	@if grep -q "549[[:space:]]\+common[[:space:]]\+ft_fork" $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; then \
		echo "Syscall 549 already exists for ft_fork. Continuing..."; \
	else \
		echo "549    common    ft_fork    sys_ft_fork" >> $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; \
	fi
	@if ! grep -q "sys_ft_fork.o" $(KERNEL_PATH)/kernel/Makefile; then \
		echo "obj-y += sys_ft_fork.o" >> $(KERNEL_PATH)/kernel/Makefile; \
	fi
	cp -f $(SRC_FORK) $(KERNEL_PATH)/kernel/sys_ft_fork.c
	@echo "Fork added or confirmed successfully."

add_kill:
	@echo "Adding kill..."
	@if grep -q "550[[:space:]]\+common[[:space:]]\+ft_kill" $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; then \
		echo "Syscall 550 already exists for ft_kill. Continuing..."; \
	else \
		echo "550    common    ft_kill    sys_ft_kill" >> $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; \
	fi
	@if ! grep -q "sys_ft_kill.o" $(KERNEL_PATH)/kernel/Makefile; then \
		echo "obj-y += sys_ft_kill.o" >> $(KERNEL_PATH)/kernel/Makefile; \
	fi
	cp -f $(SRC_KILL) $(KERNEL_PATH)/kernel/sys_ft_kill.c
	@echo "Kill added or confirmed successfully."

add_mmap:
	@echo "Adding mmap..."
	@if grep -q "551[[:space:]]\+common[[:space:]]\+ft_mmap" $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; then \
		echo "Syscall 551 already exists for ft_mmap. Continuing..."; \
	else \
		echo "551    common    ft_mmap    sys_ft_mmap" >> $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; \
	fi
	@if ! grep -q "sys_ft_mmap.o" $(KERNEL_PATH)/kernel/Makefile; then \
		echo "obj-y += sys_ft_mmap.o" >> $(KERNEL_PATH)/kernel/Makefile; \
	fi
	cp -f $(SRC_MMAP) $(KERNEL_PATH)/kernel/sys_ft_mmap.c
	@echo "Mmap added or confirmed successfully."

add_wait:
	@echo "Adding wait..."
	@if grep -q "552[[:space:]]\+common[[:space:]]\+ft_wait" $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; then \
		echo "Syscall 552 already exists for ft_wait. Continuing..."; \
	else \
		echo "552    common    ft_wait    sys_ft_wait" >> $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl; \
	fi
	@if ! grep -q "sys_ft_wait.o" $(KERNEL_PATH)/kernel/Makefile; then \
		echo "obj-y += sys_ft_wait.o" >> $(KERNEL_PATH)/kernel/Makefile; \
	fi
	cp -f $(SRC_WAIT) $(KERNEL_PATH)/kernel/sys_ft_wait.c
	@echo "Wait added or confirmed successfully."

# build_kernel:
# 	@echo "Building the kernel..."
# 	cd $(KERNEL_PATH) && make -j2
# 	@echo "Installing the kernel..."
# 	cd $(KERNEL_PATH) && make modules_install && make install
# 	@echo "Updating bootloader and rebooting..."
# 	sudo update-grub


build_kernel:
	@echo "Building only the modified files..."
	cd $(KERNEL_PATH) && make -j2 kernel/sys_get_pid_info.o
	cd $(KERNEL_PATH) && make -j2 kernel/sys_ft_fork.o
	cd $(KERNEL_PATH) && make -j2 kernel/sys_ft_kill.o
	cd $(KERNEL_PATH) && make -j2 kernel/sys_ft_mmap.o
	cd $(KERNEL_PATH) && make -j2 kernel/sys_ft_wait.o
	@echo "Rebuilding kernel image..."
	cd $(KERNEL_PATH) && make -j2 bzImage
	@echo "Installing the kernel..."
	cd $(KERNEL_PATH) && make modules_install && make install
	@echo "Updating bootloader..."
	sudo update-grub

test:
	@echo "Testing get_pid_info..."
	@dos2unix test.sh
	@sh test.sh
	@echo "Testing complete."

clean:
	@echo "Cleaning up..."
	rm -f $(KERNEL_PATH)/kernel/sys_get_pid_info.c
	sed -i '/get_pid_info/d' $(KERNEL_PATH)/arch/x86/entry/syscalls/syscall_64.tbl
	sed -i '/sys_get_pid_info.o/d' $(KERNEL_PATH)/kernel/Makefile
	@echo "Cleanup complete."

.PHONY: all add_syscall build_kernel test clean
