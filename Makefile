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

.PHONY: all test integration clean install

all: qa-siem

qa-siem: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(TEST_BIN): $(TEST_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_SRC) $(LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

integration: qa-siem
	./tests/integration.sh

clean:
	rm -rf build qa-siem

install: qa-siem
	install -D -m 0755 qa-siem $(DESTDIR)/usr/local/bin/qa-siem
	install -D -m 0644 web/index.html $(DESTDIR)/usr/share/qa-siem/web/index.html
	install -D -m 0644 web/app.js $(DESTDIR)/usr/share/qa-siem/web/app.js
	install -D -m 0644 web/style.css $(DESTDIR)/usr/share/qa-siem/web/style.css
	install -D -m 0644 config/siem.rules.json $(DESTDIR)/etc/qa-siem/rules.json
	install -D -m 0644 systemd/qa-siem.service $(DESTDIR)/etc/systemd/system/qa-siem.service
