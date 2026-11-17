CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow
CPPFLAGS += -Isrc $(shell $(PKG_CONFIG) --cflags sqlite3 libmicrohttpd libcjson openssl)
LDLIBS += $(shell $(PKG_CONFIG) --libs sqlite3 libmicrohttpd libcjson openssl) -lpthread

SRC = src/main.c src/db.c src/rules.c src/server.c src/util.c src/log.c
OBJ = $(SRC:src/%.c=build/%.o)
TEST_SRC = tests/test_core.c src/db.c src/rules.c src/util.c src/log.c
TEST_BIN = build/test_core

.PHONY: all legal legal-check test integration clean install

all: legal qa-siem

legal: legal/manifest.json
	cp legal/manifest.json web/legal.json

legal-check: legal
	python3 tests/legal.py

qa-siem: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(TEST_BIN): $(TEST_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_SRC) $(LDLIBS)

test: $(TEST_BIN) legal-check
	./$(TEST_BIN)

integration: qa-siem legal
	./tests/integration.sh

clean:
	rm -rf build qa-siem web/legal.json

install: qa-siem legal
	install -D -m 0755 qa-siem $(DESTDIR)/usr/local/bin/qa-siem
	install -D -m 0644 web/index.html $(DESTDIR)/usr/share/qa-siem/web/index.html
	install -D -m 0644 web/app.js $(DESTDIR)/usr/share/qa-siem/web/app.js
	install -D -m 0644 web/style.css $(DESTDIR)/usr/share/qa-siem/web/style.css
	install -D -m 0644 web/legal.html $(DESTDIR)/usr/share/qa-siem/web/legal.html
	install -D -m 0644 web/legal.js $(DESTDIR)/usr/share/qa-siem/web/legal.js
	install -D -m 0644 web/legal.json $(DESTDIR)/usr/share/qa-siem/web/legal.json
	install -D -m 0644 config/siem.rules.json $(DESTDIR)/etc/qa-siem/rules.json
	install -D -m 0644 systemd/qa-siem.service $(DESTDIR)/etc/systemd/system/qa-siem.service
	install -D -m 0644 LICENSE $(DESTDIR)/usr/share/doc/qa-siem/LICENSE
	install -D -m 0644 THIRD-PARTY-NOTICES.md $(DESTDIR)/usr/share/doc/qa-siem/THIRD-PARTY-NOTICES.md
	install -D -m 0644 CONTRIBUTING.md $(DESTDIR)/usr/share/doc/qa-siem/CONTRIBUTING.md
	install -D -m 0644 SECURITY.md $(DESTDIR)/usr/share/doc/qa-siem/SECURITY.md
	install -D -m 0644 docs/PRIVACY.md $(DESTDIR)/usr/share/doc/qa-siem/PRIVACY.md
	install -D -m 0644 docs/LEGAL.md $(DESTDIR)/usr/share/doc/qa-siem/LEGAL.md
	install -D -m 0644 legal/manifest.json $(DESTDIR)/usr/share/doc/qa-siem/legal/manifest.json
