all: softboundcets_rt_riscv 

#CFLAGS=-Wall -Wno-gnu-statement-expression -pedantic -O3 -D__SOFTBOUNDCETS_SPATIAL_TEMPORAL #-D__FUNC_CYCLE ##-D__SOFTBOUNDCETS_DEBUG
#CFLAGS=-Wall -pedantic -O3 -D__SOFTBOUNDCETS_SPATIAL_TEMPORAL
CFLAGS=-Wall -pedantic -O3 -D__SOFTBOUNDCETS_SPATIAL -Wno-gnu-statement-expression -D__HW_SECURITY ##-D__FUNC_CYCLE

# kenny modify to disable temporal safety
ARFLAGS=-rcs

#SOFTBOUND_CLANG=/home/lycheus/SoftBoundCETS-3.9/build/bin/clang
#RISCV_GCC=/home/lycheus/git/riscv/_install/bin/clang

# If LLVM_GOLD is set, also build a library for use with LTO
#
# Note that the name of the library is hardcoded in the compiler. Thus, we call
# it the same, but put it in the lto/ subdirectory. To use it, pass
# -L/path/to/softboundcets-lib/lto to the compiler, and use -flto during
# compilation and linking
ifneq ($(LLVM_GOLD),)
all: softboundcets_rt_lto 
endif

softboundcets_rt_riscv: softboundcets.h softboundcets-checks.c softboundcets.c softboundcets-wrappers.c
	clang $(CFLAGS) -c softboundcets-checks.c -o softboundcets-checks.o
	clang $(CFLAGS) -c softboundcets.c -o softboundcets.o
	clang $(CFLAGS) -c softboundcets-wrappers.c -o softboundcets-wrappers.o
	riscv64-unknown-linux-gnu-ar $(ARFLAGS) libsoftboundcets_rt.a softboundcets.o softboundcets-checks.o softboundcets-wrappers.o

softboundcets_rt: softboundcets.h softboundcets-checks.c softboundcets.c softboundcets-wrappers.c
	clang $(CFLAGS) -c softboundcets-checks.c -o softboundcets-checks.o
	clang $(CFLAGS) -c softboundcets.c -o softboundcets.o
	clang $(CFLAGS) -c softboundcets-wrappers.c -o softboundcets-wrappers.o
	ar $(ARFLAGS) libsoftboundcets_rt.a softboundcets.o softboundcets-checks.o softboundcets-wrappers.o

softboundcets_rt_lto: softboundcets.h softboundcets-checks.c softboundcets.c softboundcets-wrappers.c 
	mkdir lto
	clang $(CFLAGS) -flto -c softboundcets-checks.c -o lto/softboundcets-checks.lto.o
	clang $(CFLAGS) -flto -c softboundcets.c -o lto/softboundcets.lto.o
	clang $(CFLAGS) -flto -c softboundcets-wrappers.c -o lto/softboundcets-wrappers.lto.o
	ar --plugin=$(LLVM_GOLD) $(ARFLAGS) lto/libsoftboundcets_rt.a lto/softboundcets.lto.o lto/softboundcets-checks.lto.o lto/softboundcets-wrappers.lto.o

softboundcets_rt_bc: softboundcets.h softboundcets-checks.c softboundcets.c softboundcets-wrappers.c
	clang $(CFLAGS) -emit-llvm -c softboundcets-checks.c -o softboundcets-checks.bc
	clang $(CFLAGS) -emit-llvm -c softboundcets.c -o softboundcets.bc
	clang $(CFLAGS) -emit-llvm -c softboundcets-wrappers.c -o softboundcets-wrappers.bc

clean:
	rm -rf *.o *.a *.ll *.s  *~ lto/ *.bc
