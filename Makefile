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
# build. Use -MD (rather than -MMD) so ABI-affecting Quicly and picotls headers
# are still tracked as dependencies.
DEPFLAGS = -MD -MP

# Include paths: use -isystem for quicly and picotls to suppress warning headers
INCLUDES = -Isrc/common -Ideps/nanors -Ideps/nanors/deps/obl -Ideps/nanorq/include -Ideps/nanorq/deps -Ideps/pathflow -Ideps/pathflow/solvers -isystem deps/quicly/include -isystem deps/quicly/deps/picotls/include -Ideps/quicly/deps/klib $(INCLUDES_OPENSSL)

QUICLY_SRCS = deps/quicly/lib/quicly.c \
              deps/quicly/lib/flexicast.c \
              deps/quicly/lib/flexicast_cc.c \
              deps/quicly/lib/flexicast_cc_multicast.c \
              deps/quicly/lib/flexicast_cc_adaptive.c \
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

TRANSPORT_OBJS = src/common/cli_parse.o \
              src/common/transport_config.o \
              src/common/qlinq.o \
              src/common/transport_egress.o \
              src/common/transport_fec_state.o \
              src/common/transport_flexicast.o \
              src/common/transport_flexicast_dispatch.o \
              src/common/transport_flexicast_repair.o \
              src/common/transport_memory.o \
              src/common/transport_paths.o \
              src/common/transport_protocol.o \
              src/common/transport_publish.o \
              src/common/transport_repair.o \
              src/common/transport_repair_planner.o \
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
CAST_OBJS = src/cast/main.o

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

all: qlinqd qlinq-app qlinq-cast qlinq-tund qlinq-tun

libqlinq.a: $(TRANSPORT_OBJS)
	$(AR) rcs $@ $(TRANSPORT_OBJS)

qlinqd: $(DAEMON_OBJS)
	$(CC) -o $@ $(DAEMON_OBJS) $(LDFLAGS)

qlinq-app: $(APP_OBJS) libqlinq.a
	$(CC) -o $@ $(APP_OBJS) libqlinq.a $(LDFLAGS)

qlinq-cast: $(CAST_OBJS) libqlinq.a
	$(CC) -o $@ $(CAST_OBJS) libqlinq.a $(LDFLAGS)

qlinq-tund: src/host/linux/tund.o src/host/linux/tun_device.o
	$(CC) -o $@ $^ $(LDFLAGS)

qlinq-tun: src/host/linux/tun_direct.o src/host/linux/tun_device.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

examples/data_multipath_benchmark: examples/data_multipath_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ examples/data_multipath_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_fec: t/00util/test_fec.o $(FEC_OBJS)
	$(CC) -o $@ t/00util/test_fec.o $(FEC_OBJS) $(LDFLAGS)

t/00util/test_egress_errors: t/00util/test_egress_errors.o src/common/transport_egress.o
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_transport_bind: t/00util/test_transport_bind.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_interleaved_receive: t/00util/test_interleaved_receive.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_publication_limits: t/00util/test_publication_limits.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_directional_subscriptions: t/00util/test_directional_subscriptions.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_qlinq_event_overflow: t/00util/test_qlinq_event_overflow.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_qlinq_compat: t/00util/test_qlinq_compat.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_qlinq_reconnect: t/00util/test_qlinq_reconnect.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_qlinq_delivery: t/00util/test_qlinq_delivery.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_qlinq_event_ownership: t/00util/test_qlinq_event_ownership.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_generic_ports: t/00util/test_generic_ports.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_stream_budget: t/00util/test_stream_budget.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_transport: t/00util/test_transport.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_transport.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_reliable_bidirectional: t/00util/test_reliable_bidirectional.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_flexicast_transport: t/00util/test_flexicast_transport.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_flexicast_transport.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_flexicast_regressions: t/00util/test_flexicast_regressions.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_quicly_flexicast: deps/quicly/t/flexicast.c deps/quicly/t/flexicast-main.c deps/quicly/deps/picotest/picotest.c $(QUICLY_OBJS)
	$(CC) $(CFLAGS_COMMON) $(INCLUDES) $(CFLAGS) -Ideps/quicly/deps/picotest -o $@ $^ $(LDFLAGS)

t/00util/test_flexicast_scale: t/00util/test_flexicast_scale.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_flexicast_scale.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_tund: t/00util/test_tund.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_tund.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_data_uds: t/00util/test_data_uds.o src/common/data_uds.o
	$(CC) -o $@ t/00util/test_data_uds.o src/common/data_uds.o $(LDFLAGS)

t/00util/test_transport_wire: t/00util/test_transport_wire.o src/common/transport_wire.o
	$(CC) -o $@ t/00util/test_transport_wire.o src/common/transport_wire.o $(LDFLAGS)

t/00util/test_transport_components: t/00util/test_transport_components.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_transport_components.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/test_qlinq_api: t/00util/test_qlinq_api.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_qlinq_api.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/fuzz_transport_wire: t/00util/fuzz_transport_wire.c src/common/transport_wire.c
	clang $(CFLAGS_COMMON) $(INCLUDES) -fsanitize=fuzzer,address,undefined \
		-o $@ t/00util/fuzz_transport_wire.c src/common/transport_wire.c

t/00util/fuzz_flexicast_frames: t/00util/fuzz_flexicast_frames.c $(QUICLY_OBJS)
	clang $(CFLAGS_COMMON) $(INCLUDES) -fsanitize=fuzzer,address,undefined \
		-o $@ t/00util/fuzz_flexicast_frames.c deps/quicly/lib/flexicast.c \
		$(filter-out deps/quicly/lib/flexicast.o,$(QUICLY_OBJS)) $(LDFLAGS)

t/00util/fuzz_flexicast_state: t/00util/fuzz_flexicast_state.c $(COMMON_OBJS)
	clang $(CFLAGS_COMMON) $(INCLUDES) -fsanitize=fuzzer,address,undefined -fno-sanitize=pointer-overflow \
		-o $@ t/00util/fuzz_flexicast_state.c deps/quicly/lib/flexicast.c \
		src/common/transport_fec_state.c \
		$(filter-out deps/quicly/lib/flexicast.o src/common/transport_fec_state.o,$(COMMON_OBJS)) $(LDFLAGS)

fuzz-flexicast-state: t/00util/fuzz_flexicast_state
	ASAN_OPTIONS=detect_leaks=1 ./t/00util/fuzz_flexicast_state -runs=10000 -max_len=1024 -len_control=0

fuzz-wire: t/00util/fuzz_transport_wire
	ASAN_OPTIONS=detect_leaks=0 ./t/00util/fuzz_transport_wire -runs=10000

fuzz-flexicast: t/00util/fuzz_flexicast_frames
	ASAN_OPTIONS=detect_leaks=0 ./t/00util/fuzz_flexicast_frames -runs=10000

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
	$(MAKE) fuzz-flexicast
	$(MAKE) fuzz-flexicast-state
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

CHECK_BINARIES = t/00util/test_fec \
	t/00util/test_egress_errors t/00util/test_transport_bind \
	t/00util/test_interleaved_receive t/00util/test_publication_limits \
	t/00util/test_directional_subscriptions \
	t/00util/test_qlinq_event_overflow t/00util/test_qlinq_compat \
	t/00util/test_qlinq_reconnect t/00util/test_qlinq_delivery \
	t/00util/test_qlinq_event_ownership t/00util/test_generic_ports \
	t/00util/test_stream_budget t/00util/test_transport \
	t/00util/test_flexicast_transport t/00util/test_flexicast_scale \
	t/00util/test_flexicast_regressions t/00util/test_quicly_flexicast \
	t/00util/test_qlinq_api \
	t/00util/test_reliable_bidirectional t/00util/test_tund \
	t/00util/test_data_uds t/00util/test_transport_wire \
	t/00util/test_transport_components t/00util/test_multipath \
	t/00util/test_multipath_nack t/00util/test_operational t/00util/test_tls

check: all $(CHECK_BINARIES) gencerts
	prove -I. -v t/*.t

clean: 
	rm -f qlinqd qlinq-app qlinq-cast qlinq-tund libqlinq.a t/00util/test_fec t/00util/test_transport t/00util/test_flexicast_transport t/00util/test_flexicast_scale t/00util/test_flexicast_regressions t/00util/test_qlinq_delivery t/00util/test_egress_errors t/00util/test_quicly_flexicast t/00util/test_tund t/00util/test_data_uds t/00util/test_transport_wire t/00util/test_transport_components t/00util/test_qlinq_api t/00util/test_qlinq_reconnect t/00util/fuzz_transport_wire t/00util/fuzz_flexicast_frames t/00util/fuzz_flexicast_state t/00util/test_multipath t/00util/test_multipath_nack t/00util/test_operational t/00util/test_tls t/00util/test_benchmark t/00util/test_rateless_benchmark t/00util/test_tc_benchmark examples/data_multipath_benchmark
	find src deps t examples -name "*.o" -delete
	find src t examples -name "*.d" -delete
	rm -f $(QUICLY_OBJS:.o=.d) $(NANORQ_OBJS:.o=.d) \
		$(PATHFLOW_OBJS:.o=.d) deps/nanors/rs.d \
		deps/nanors/deps/obl/oblas_common.d \
		deps/nanors/deps/obl/oblas_lite.d

# Optional Linux integration suite. It uses root/CAP_NET_ADMIN or an
# unprivileged user namespace to verify native IPv4/IPv6 SSM across a bridge.
check-flexicast-netns: t/00util/test_flexicast_transport gencerts
	./t/netns_flexicast_ssm.sh


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

.PHONY: all clean check check-flexicast-netns benchmark fuzz-wire \
	fuzz-flexicast fuzz-flexicast-state \
	check-submodules check-multipath-demo check-sanitize soak release-check \
	indent gencerts

-include $(shell find src t examples -name "*.d" -print 2>/dev/null) \
         $(QUICLY_OBJS:.o=.d) $(NANORQ_OBJS:.o=.d) \
         $(PATHFLOW_OBJS:.o=.d) deps/nanors/rs.d \
         deps/nanors/deps/obl/oblas_common.d \
         deps/nanors/deps/obl/oblas_lite.d
