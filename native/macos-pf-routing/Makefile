CC = clang
CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror
OBJCFLAGS = -Wno-deprecated-declarations
LDFLAGS = -framework Foundation -framework AppKit -framework Security -lbsm
OUT ?= build/envara-pf-native

.PHONY: all fixture pf-fixture test test-pf-fixture clean
all: $(OUT)

NATIVE_SOURCES = main.c launcher.c tunnel.c transport.c pf-hook.c pf-run-ledger.c pf-filter-command.c pf-filter-transaction.c app-command.c app-control.c app-ticket.c app-registry.c app-supervisor.c gui-launch.m launch-guardian.c pf-production-filter.c app-native-factory.m app-scope-proof.c app-transport.c notion-launch.m app-keychain.m
NATIVE_HEADERS = journal-retirement.c journal-retirement.h app-family.c app-family.h native.h pf-hook.h pf-hook-abi.h pf-run-ledger.h pf-filter-command.h pf-filter-transaction.h app-command.h app-control.h app-ticket.h app-registry.h app-supervisor.h gui-launch.h launch-guardian.h pf-production-filter.h app-native-factory.h app-scope-proof.h app-transport.h transport-session.h notion-launch.h app-keychain.h

$(OUT): $(NATIVE_SOURCES) $(NATIVE_HEADERS)
	mkdir -p $(dir $(OUT))
	$(CC) $(CFLAGS) $(OBJCFLAGS) $(NATIVE_SOURCES) $(LDFLAGS) -o $(OUT)

fixture: $(OUT)
	$(OUT) status
	$(OUT) fixture

PF_FIXTURE_OUT ?= build/EnvaraRoutingAcceptanceFixture
PF_FIXTURE_SOURCES = fixture/Entry.swift fixture/FixtureProtocol.swift fixture/FixtureProbe.swift fixture/FixtureRuntime.swift fixture/ProcessIdentity.swift

$(PF_FIXTURE_OUT): $(PF_FIXTURE_SOURCES)
	mkdir -p $(dir $(PF_FIXTURE_OUT))
	xcrun swiftc -O -parse-as-library -target arm64-apple-macos13.0 $(PF_FIXTURE_SOURCES) -o $(PF_FIXTURE_OUT)

pf-fixture: $(PF_FIXTURE_OUT)

test-pf-fixture: $(PF_FIXTURE_OUT)
	node fixture-reservation.test.mjs

test: $(OUT)
	node test.mjs

clean:
	rm -f $(OUT) $(PF_FIXTURE_OUT)
