TARGETS := test core test.ctf test.dwarf2ctf
DOCKER := podman
IMAGE := "container-registry.oracle.com/os/oraclelinux:7"

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -f $(TARGETS)

test: test.c
	gcc -g -o test test.c

core: test
	ulimit -c unlimited; ./test; coredumpctl dump >core
	touch core

test.ctf: test.c
	gcc -gctf -Wl,--ctf-variables -o test.ctf test.c

test.dwarf2ctf: test.c build_dwarf2ctf.sh
	$(DOCKER) run -it \
	    --volume "$(shell pwd)":/io \
	    --workdir /io \
	    --hostname drgn \
	    --rm \
	    --pull always \
	    $(IMAGE) \
	    /io/build_dwarf2ctf.sh test.c test.dwarf2ctf
