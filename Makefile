# Makefile for qlinq

CC = gcc
ARCH = $(shell uname -m)

# Default CFLAGS for our code
CFLAGS_COMMON = -Wvla -Wall -Wextra -std=c11 -g -D_GNU_SOURCE -D_DEFAULT_SOURCE -DPATHFLOW_ARENA_SIZE=65536

# Include paths: use -isystem for quicly and picotls to suppress warning headers
INCLUDES = -Isrc/common -Ideps/nanors -Ideps/nanors/deps/obl -Ideps/nanorq/include -Ideps/nanorq/deps -Ideps/pathflow -Ideps/pathflow/solvers -isystem deps/quicly/include -isystem deps/quicly/deps/picotls/include -Ideps/quicly/deps/klib

LDFLAGS = -lpthread -lrt -ldl -lm -lcrypto -lssl

QUICLY_SRCS = deps/quicly/lib/quicly.c \
              deps/quicly/lib/defaults.c \
              deps/quicly/lib/frame.c \
              deps/quicly/lib/local_cid.c \
              deps/quicly/lib/loss.c \
              deps/quicly/lib/ranges.c \
              deps/quicly/lib/rate.c \
              deps/quicly/lib/recvstate.c \
              deps/quicly/lib/remote_cid.c \
              deps/quicly/lib/sendstate.c \
              deps/quicly/lib/sentmap.c \
              deps/quicly/lib/streambuf.c \
              deps/quicly/lib/cc-reno.c \
              deps/quicly/lib/cc-cubic.c \
              deps/quicly/lib/cc-pico.c \
              deps/quicly/deps/picotls/lib/picotls.c \
              deps/quicly/deps/picotls/lib/openssl.c \
              deps/quicly/deps/picotls/lib/pembase64.c \
              deps/quicly/deps/picotls/lib/hpke.c \
              deps/quicly/deps/picotls/lib/asn1.c

NANORQ_SRCS = deps/nanorq/lib/chooser.c \
              deps/nanorq/lib/nanorq_core.c \
              deps/nanorq/lib/ops.c \
              deps/nanorq/lib/params.c \
              deps/nanorq/lib/precode.c \
              deps/nanorq/lib/rand.c \
              deps/nanorq/lib/tuple.c \
              deps/nanorq/lib/uvec.c

PATHFLOW_SRCS = deps/pathflow/pathflow.c

IFMON_SRCS = src/common/ifmon.c

QUICLY_OBJS = $(QUICLY_SRCS:.c=.o)
NANORQ_OBJS = $(NANORQ_SRCS:.c=.o)
PATHFLOW_OBJS = $(PATHFLOW_SRCS:.c=.o)
IFMON_OBJS = $(IFMON_SRCS:.c=.o)

COMMON_OBJS = src/common/data_uds.o \
              src/common/transport_quicly.o \
              src/common/fec.o \
              deps/nanors/rs.o \
              deps/nanors/deps/obl/oblas_common.o \
              deps/nanors/deps/obl/oblas_lite.o \
              $(QUICLY_OBJS) \
              $(NANORQ_OBJS) \
              $(PATHFLOW_OBJS) \
              $(IFMON_OBJS)

DAEMON_OBJS = src/daemon/main.o \
              $(COMMON_OBJS)

FEC_OBJS = src/common/fec.o \
           deps/nanors/rs.o \
           deps/nanors/deps/obl/oblas_common.o \
           deps/nanors/deps/obl/oblas_lite.o \
           $(NANORQ_OBJS) \
           $(PATHFLOW_OBJS)

# Rules to compile our source files with full warnings
src/%.o: src/%.c
	$(CC) $(CFLAGS_COMMON) $(INCLUDES) $(CFLAGS) -c $< -o $@

examples/%.o: examples/%.c
	$(CC) $(CFLAGS_COMMON) $(INCLUDES) $(CFLAGS) -c $< -o $@

t/%.o: t/%.c
	$(CC) $(CFLAGS_COMMON) $(INCLUDES) $(CFLAGS) -c $< -o $@

# Rule to compile third-party deps and suppress all warnings with -w
deps/%.o: deps/%.c
	$(CC) $(INCLUDES) $(CFLAGS) -w -c $< -o $@

all: patch-quicly qlinqd qlinq-tund

patch-quicly:

unpatch-quicly:

qlinqd: patch-quicly $(DAEMON_OBJS)
	$(CC) -o $@ $(DAEMON_OBJS) $(LDFLAGS)

qlinq-tund: src/host/linux/tund.c
	$(CC) $(CFLAGS_COMMON) $(INCLUDES) -o $@ src/host/linux/tund.c

examples/data_multipath_benchmark: patch-quicly examples/data_multipath_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ examples/data_multipath_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_fec: t/00util/test_fec.o $(FEC_OBJS)
	$(CC) -o $@ t/00util/test_fec.o $(FEC_OBJS) $(LDFLAGS)

t/00util/test_transport: patch-quicly t/00util/test_transport.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_transport.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_tund: patch-quicly t/00util/test_tund.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_tund.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_benchmark: patch-quicly t/00util/test_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_tc_benchmark: patch-quicly t/00util/test_tc_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_tc_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_multipath: patch-quicly t/00util/test_multipath.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_multipath.o $(COMMON_OBJS) $(LDFLAGS)

benchmark: t/00util/test_benchmark
	./t/00util/test_benchmark

clean: unpatch-quicly
	rm -f qlinqd qlinq-tund t/00util/test_fec t/00util/test_transport t/00util/test_tund t/00util/test_multipath t/00util/test_benchmark t/00util/test_tc_benchmark examples/data_multipath_benchmark
	find src deps t examples -name "*.o" -delete

check: patch-quicly qlinq-tund t/00util/test_fec t/00util/test_transport t/00util/test_tund t/00util/test_multipath gencerts
	prove -I. -v t/*.t

t/assets/server.crt t/assets/server.key:
	mkdir -p t/assets
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout t/assets/server.key -out t/assets/server.crt -subj "/CN=localhost"

gencerts: t/assets/server.crt t/assets/server.key

indent:
	clang-format -style=LLVM -i src/common/*.c src/common/*.h src/host/linux/*.c examples/*.c t/00util/*.c

.PHONY: all clean check patch-quicly unpatch-quicly benchmark indent gencerts
