# AEGIS-ZERO build & verification targets.
#   macOS : make verify-darwin
#   Linux : make vmlinux build-bpf verify-bpf      (inside the Lima VM: make lima-up lima-verify)

PY        ?= python3
CLANG     ?= clang
BPFTOOL   ?= bpftool
ARCH      := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/arm64/arm64/')
BPF_OBJ   := aegis_kernel_hook.bpf.o
PIN_DIR   := /sys/fs/bpf/aegis
AEGIS_TMP := /tmp/aegis_canaries_* /tmp/aegis_cow_* /tmp/aegis_work_* /tmp/aegis_demo_* /tmp/aegis_keys_* /tmp/aegis_bridge_* /tmp/aegis_oob.sock /tmp/aegis_dashboard_* /tmp/aegis_run_* /tmp/aegis_dbguard_* /tmp/aegis_swarm_* /tmp/aegis_forensics_*
LIMA_VM   ?= aegis-ebpf

.PHONY: all vmlinux build-bpf verify-bpf unload-bpf verify-darwin test-controller test-proxy test-bridge \
        test-dashboard test-runner test-dbguard test-swarm test-forensics lima-up lima-verify lima-shell clean

all: verify-darwin

vmlinux: vmlinux.h
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

build-bpf: $(BPF_OBJ)
$(BPF_OBJ): aegis_kernel_hook.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I/usr/include/$(shell uname -m)-linux-gnu \
		-c aegis_kernel_hook.bpf.c -o $(BPF_OBJ)

# Loads into the kernel verifier and attaches all LSM programs (requires root, bpf in lsm=).
verify-bpf: $(BPF_OBJ)
	@grep -qw bpf /sys/kernel/security/lsm || (echo "BPF LSM not active: check lsm= boot param" && exit 1)
	sudo mkdir -p $(PIN_DIR)
	sudo $(BPFTOOL) prog loadall $(BPF_OBJ) $(PIN_DIR)/progs pinmaps $(PIN_DIR)/maps autoattach
	sudo $(BPFTOOL) prog show | grep -E 'lsm .*aegis_'
	sudo ls $(PIN_DIR)/maps
	sudo $(PY) -B aegis_bpf_bridge.py --test
	$(MAKE) unload-bpf

unload-bpf:
	sudo rm -rf $(PIN_DIR)

test-controller:
	$(PY) -B aegis_controller.py

test-proxy:
	$(PY) -B aegis_proxy.py --demo

test-bridge:
	$(PY) -B aegis_bpf_bridge.py --test

test-dashboard:
	$(PY) -B aegis_dashboard.py --self-test

test-runner:
	$(PY) -B aegis_run.py --self-test

test-dbguard:
	$(PY) -B aegis_db_guard.py --self-test

test-swarm:
	$(PY) -B aegis_swarm.py --self-test

test-forensics:
	$(PY) -B aegis_forensics.py --self-test

verify-darwin: test-controller test-proxy test-bridge test-dashboard test-runner test-dbguard test-swarm test-forensics
	@leftover=$$(ls -A | grep -E '^(\.aegis_canaries|__pycache__|.*\.aegis_rb)$$' || true); \
	 if [ -n "$$leftover" ]; then echo "workspace artifacts left: $$leftover"; exit 1; fi; \
	 if ls -d $(AEGIS_TMP) 2>/dev/null; then echo "tmp artifacts left"; exit 1; fi; \
	 echo "verify-darwin: ALL PASS, workspace clean"

lima-up:
	limactl start --name=$(LIMA_VM) --tty=false lima-ebpf.yaml
	limactl restart $(LIMA_VM)   # reboot once so the new lsm= cmdline takes effect

lima-verify:
	limactl shell --workdir $(CURDIR) $(LIMA_VM) -- make vmlinux build-bpf verify-bpf

lima-shell:
	limactl shell --workdir $(CURDIR) $(LIMA_VM)

clean:
	rm -rf vmlinux.h $(BPF_OBJ) __pycache__ .aegis_canaries build dist *.egg-info
	rm -rf $(AEGIS_TMP)
