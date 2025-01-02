KERNEL_PATH := /home/jareste/ft_linux/linux-6.12.6
SRC := srcs/syscall.c

all: add_syscall build_kernel

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

build_kernel:
	@echo "Building the kernel..."
	cd $(KERNEL_PATH) && make -j2
	@echo "Installing the kernel..."
	cd $(KERNEL_PATH) && make modules_install && make install
	@echo "Updating bootloader and rebooting..."
	sudo update-grub


# build_kernel:
# 	@echo "Building only the modified files..."
# 	cd $(KERNEL_PATH) && make -j2 kernel/sys_get_pid_info.o
# 	@echo "Rebuilding kernel image..."
# 	cd $(KERNEL_PATH) && make -j2 bzImage
# 	@echo "Installing the kernel..."
# 	cd $(KERNEL_PATH) && make modules_install && make install
# 	@echo "Updating bootloader..."
# 	sudo update-grub

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
