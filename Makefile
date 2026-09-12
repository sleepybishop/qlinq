# Makefile for qlinq

CC = gcc
ARCH = $(shell uname -m)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(origin AR),default)
    AR := $(shell xcrun -find ar 2>/dev/null || echo ar)
  endif
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl)
  OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null || echo -I$(OPENSSL_PREFIX)/include)
  OPENSSL_LIBS   ?= $(shell pkg-config --libs openssl 2>/dev/null || echo -L$(OPENSSL_PREFIX)/lib -lcrypto -lssl)
  INCLUDES_OPENSSL = $(OPENSSL_CFLAGS)
  LDFLAGS = $(OPENSSL_LIBS) -lpthread -ldl -lm
else
  INCLUDES_OPENSSL =
  LDFLAGS = -lpthread -lrt -ldl -lm -lcrypto -lssl
endif

# Default CFLAGS for our code
CFLAGS_COMMON = -Wvla -Wall -Wextra -std=c11 -g -D_GNU_SOURCE -D_DEFAULT_SOURCE -DPATHFLOW_ARENA_SIZE=65536
# Quicly's encoder capacity helpers intentionally perform arithmetic from a
# null base pointer. Exclude that one UBSan check while retaining ASan and all
# other undefined-behavior checks across qlinq and its linked dependencies.
SANITIZER_FLAGS = -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize=pointer-overflow
# Quicly is included with -isystem to keep third-party warnings out of qlinq's
# build. Use -MD so ABI-affecting Quicly and picotls headers remain tracked.
DEPFLAGS = -MD -MP

# Include paths: use -isystem for quicly and picotls to suppress warning headers
INCLUDES = -Isrc/common -Ideps/nanors -Ideps/nanors/deps/obl -Ideps/nanorq/include -Ideps/nanorq/deps -Ideps/pathflow -Ideps/pathflow/solvers -isystem deps/quicly/include -isystem deps/quicly/deps/picotls/include -Ideps/quicly/deps/klib $(INCLUDES_OPENSSL)

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

TRANSPORT_OBJS = src/common/transport_config.o \
              src/common/transport_egress.o \
              src/common/transport_fec_state.o \
              src/common/transport_memory.o \
              src/common/transport_paths.o \
              src/common/transport_protocol.o \
              src/common/transport_publish.o \
              src/common/transport_repair.o \
              src/common/transport_scheduler.o \
              src/common/transport_stream.o \
              src/common/transport_subscriptions.o \
              src/common/transport_tls.o \
              src/common/transport_tracks.o \
              src/common/transport_udp.o \
              src/common/transport_wire.o \
              src/common/transport_quicly.o \
              src/common/fec.o \
              deps/nanors/rs.o \
              deps/nanors/deps/obl/oblas_common.o \
              deps/nanors/deps/obl/oblas_lite.o \
              $(QUICLY_OBJS) \
              $(NANORQ_OBJS) \
              $(PATHFLOW_OBJS) \
              $(IFMON_OBJS)

COMMON_OBJS = src/common/data_uds.o \
              $(TRANSPORT_OBJS)

DAEMON_OBJS = src/daemon/main.o \
              $(COMMON_OBJS)

APP_OBJS = src/app/main.o

FEC_OBJS = src/common/fec.o \
           deps/nanors/rs.o \
           deps/nanors/deps/obl/oblas_common.o \
           deps/nanors/deps/obl/oblas_lite.o \
           $(NANORQ_OBJS) \
           $(PATHFLOW_OBJS)

# Rules to compile our source files with full warnings
src/%.o: src/%.c
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) -c $< -o $@

examples/%.o: examples/%.c
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) -c $< -o $@

t/%.o: t/%.c
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) -c $< -o $@

# Rule to compile third-party deps and suppress all warnings with -w
deps/%.o: deps/%.c
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) -w -c $< -o $@

all: qlinqd qlinq-app qlinq-tund

libqlinq.a: $(TRANSPORT_OBJS)
	$(AR) rcs $@ $(TRANSPORT_OBJS)

qlinqd: $(DAEMON_OBJS)
	$(CC) -o $@ $(DAEMON_OBJS) $(LDFLAGS)

qlinq-app: $(APP_OBJS) libqlinq.a
	$(CC) -o $@ $(APP_OBJS) libqlinq.a $(LDFLAGS)

qlinq-tund: src/host/linux/tund.c
	$(CC) $(CFLAGS_COMMON) $(INCLUDES) $(CFLAGS) -o $@ src/host/linux/tund.c \
		$(LDFLAGS)

examples/data_multipath_benchmark: examples/data_multipath_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ examples/data_multipath_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_fec: t/00util/test_fec.o $(FEC_OBJS)
	$(CC) -o $@ t/00util/test_fec.o $(FEC_OBJS) $(LDFLAGS)

t/00util/test_transport: t/00util/test_transport.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_transport.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_reliable_bidirectional: t/00util/test_reliable_bidirectional.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_reliable_bidirectional.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_tund: t/00util/test_tund.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_tund.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_data_uds: t/00util/test_data_uds.o src/common/data_uds.o
	$(CC) -o $@ t/00util/test_data_uds.o src/common/data_uds.o $(LDFLAGS)

t/00util/test_transport_wire: t/00util/test_transport_wire.o src/common/transport_wire.o
	$(CC) -o $@ t/00util/test_transport_wire.o src/common/transport_wire.o $(LDFLAGS)

t/00util/test_transport_components: t/00util/test_transport_components.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_transport_components.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/fuzz_transport_wire: t/00util/fuzz_transport_wire.c src/common/transport_wire.c
	clang $(CFLAGS_COMMON) $(INCLUDES) -fsanitize=fuzzer,address,undefined \
		-o $@ t/00util/fuzz_transport_wire.c src/common/transport_wire.c

fuzz-wire: t/00util/fuzz_transport_wire
	ASAN_OPTIONS=detect_leaks=0 ./t/00util/fuzz_transport_wire -runs=10000

check-submodules:
	./scripts/check_submodules.sh

check-multipath-demo:
	@if [ "$${QLINQ_SKIP_PRIVILEGED:-0}" = 1 ]; then \
		echo "SKIP privileged multipath demo (QLINQ_SKIP_PRIVILEGED=1)"; \
	else \
		./examples/multipath_demo.sh; \
	fi

check-sanitize:
	$(MAKE) clean
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(MAKE) check CC=clang CFLAGS="$(SANITIZER_FLAGS)" \
		LDFLAGS="$(SANITIZER_FLAGS) $(LDFLAGS)"

soak: t/00util/test_operational t/00util/test_transport \
	t/00util/test_multipath_nack gencerts
	./scripts/operational_soak.sh

release-check: check-submodules
	$(MAKE) clean
	$(MAKE) check
	$(MAKE) fuzz-wire
	$(MAKE) check-sanitize
	$(MAKE) clean
	$(MAKE) all examples/data_multipath_benchmark gencerts
	$(MAKE) check-multipath-demo
	@echo "=== RELEASE CHECK OK ==="

t/00util/test_benchmark: t/00util/test_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_tc_benchmark: t/00util/test_tc_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_tc_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_multipath: t/00util/test_multipath.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_multipath.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_multipath_nack: t/00util/test_multipath_nack.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_multipath_nack.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_operational: t/00util/test_operational.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_operational.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_tls: t/00util/test_tls.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_tls.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_rateless_benchmark: t/00util/test_rateless_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_rateless_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

benchmark: t/00util/test_benchmark
	./t/00util/test_benchmark

benchmark-rateless: t/00util/test_rateless_benchmark
	./t/00util/test_rateless_benchmark

clean: 
	rm -f qlinqd qlinq-app qlinq-tund libqlinq.a t/00util/test_fec t/00util/test_transport t/00util/test_reliable_bidirectional t/00util/test_tund t/00util/test_data_uds t/00util/test_transport_wire t/00util/test_transport_components t/00util/fuzz_transport_wire t/00util/test_multipath t/00util/test_multipath_nack t/00util/test_operational t/00util/test_tls t/00util/test_benchmark t/00util/test_rateless_benchmark t/00util/test_tc_benchmark examples/data_multipath_benchmark
	find src deps t examples -name "*.o" -delete
	find src t examples -name "*.d" -delete
	rm -f $(QUICLY_OBJS:.o=.d) $(NANORQ_OBJS:.o=.d) \
		$(PATHFLOW_OBJS:.o=.d) deps/nanors/rs.d \
		deps/nanors/deps/obl/oblas_common.d \
		deps/nanors/deps/obl/oblas_lite.d

check: qlinqd qlinq-app qlinq-tund t/00util/test_fec t/00util/test_transport t/00util/test_reliable_bidirectional t/00util/test_tund t/00util/test_data_uds t/00util/test_transport_wire t/00util/test_transport_components t/00util/test_multipath t/00util/test_multipath_nack t/00util/test_operational t/00util/test_tls gencerts
	prove -I. -v t/*.t

t/assets/server.crt t/assets/server.key &:
	mkdir -p t/assets
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout t/assets/server.key -out t/assets/server.crt -subj "/CN=localhost"

t/assets/verified.crt t/assets/verified.key &:
	mkdir -p t/assets
	openssl req -x509 -nodes -days 7 -newkey rsa:2048 \
		-keyout t/assets/verified.key -out t/assets/verified.crt \
		-subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
		-addext "extendedKeyUsage=serverAuth,clientAuth"

t/assets/verified-v6.crt t/assets/verified-v6.key &:
	mkdir -p t/assets
	openssl req -x509 -nodes -days 7 -newkey rsa:2048 \
		-keyout t/assets/verified-v6.key -out t/assets/verified-v6.crt \
		-subj "/CN=localhost" -addext "subjectAltName=IP:::1,DNS:localhost" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
		-addext "extendedKeyUsage=serverAuth,clientAuth"

t/assets/untrusted.crt t/assets/untrusted.key &:
	mkdir -p t/assets
	openssl req -x509 -nodes -days 7 -newkey rsa:2048 \
		-keyout t/assets/untrusted.key -out t/assets/untrusted.crt \
		-subj "/CN=untrusted" -addext "basicConstraints=critical,CA:TRUE"

t/assets/unsafe.key: t/assets/verified.key
	cp $< $@
	chmod 0644 $@

gencerts: t/assets/server.crt t/assets/server.key t/assets/verified.crt t/assets/verified.key t/assets/verified-v6.crt t/assets/verified-v6.key t/assets/untrusted.crt t/assets/untrusted.key t/assets/unsafe.key

indent:
	clang-format -style=LLVM -i src/common/*.c src/common/*.h src/host/linux/*.c examples/*.c t/00util/*.c

.PHONY: all clean check benchmark fuzz-wire check-submodules \
	check-multipath-demo check-sanitize soak release-check indent gencerts

-include $(shell find src t examples -name "*.d" -print 2>/dev/null) \
         $(QUICLY_OBJS:.o=.d) $(NANORQ_OBJS:.o=.d) \
         $(PATHFLOW_OBJS:.o=.d) deps/nanors/rs.d \
         deps/nanors/deps/obl/oblas_common.d \
         deps/nanors/deps/obl/oblas_lite.d
