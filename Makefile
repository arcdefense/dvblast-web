VERSION_MAJOR = 3
VERSION_MINOR = 5
TOPDIR = `basename ${PWD}`
GIT_VER = $(shell git describe --tags --dirty --always 2>/dev/null)
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
deltacast_inc := $(shell sh -c 'test -f /usr/include/StreamMaster.h && echo -n Y')

CFLAGS ?= -O3 -fomit-frame-pointer -g
CFLAGS += -Wall -Wformat-security -Wno-strict-aliasing -MMD -MP
CFLAGS += -I. -Imodules $(shell pkg-config --cflags libmicrohttpd jansson 2>/dev/null)
CFLAGS += -DVERSION=\"$(VERSION_MAJOR).$(VERSION_MINOR)\"
CFLAGS += -DVERSION_MAJOR=$(VERSION_MAJOR)
CFLAGS += -DVERSION_MINOR=$(VERSION_MINOR)
ifneq "$(GIT_VER)" ""
CFLAGS += -DVERSION_EXTRA=\"git-$(GIT_VER)\"
else
CFLAGS += -DVERSION_EXTRA=\"release\"
endif

ifeq ($(uname_S),Linux)
LDLIBS += -lrt
endif
ifeq ($(uname_S),Darwin)
LDLIBS += -liconv
endif

ifeq ($(deltacast_inc),Y)
CFLAGS += -DHAVE_ASI_DELTACAST_SUPPORT
LDLIBS += -lstreammaster
endif

# DVB-CSA Support: Check for system libdvbcsa first; fallback to internal implementation
HAVE_LIBDVBCSA := $(shell pkg-config --exists libdvbcsa 2>/dev/null && echo Y)
ifeq ($(HAVE_LIBDVBCSA),Y)
CFLAGS += -DHAVE_LIBDVBCSA $(shell pkg-config --cflags libdvbcsa 2>/dev/null)
LDLIBS_DVBCSA = $(shell pkg-config --libs libdvbcsa 2>/dev/null)
OBJ_DVBCSA =
else
CFLAGS += -Idvbcsa
LDLIBS_DVBCSA =
OBJ_DVBCSA = dvbcsa/dvbcsa_algo.o dvbcsa/dvbcsa_block.o dvbcsa/dvbcsa_key.o dvbcsa/dvbcsa_stream.o
endif

LDLIBS_DVBLAST += -lpthread -lev -lm $(shell pkg-config --libs libmicrohttpd jansson openssl 2>/dev/null) $(LDLIBS_DVBCSA)

OBJ_MODULES = modules/softcam/softcam.o modules/cas/cas.o modules/http_play/http_play.o modules/http_auth/http_auth.o modules/hls/hls.o modules/epg/epg.o modules/general/general.o modules/groups/groups.o modules/ws/ws.o modules/analyzer/analyzer.o
OBJ_WEB = web_state.o web_manager.o web_server.o web_ui_embed.o $(OBJ_MODULES)

OBJ_DVBLAST = dvblast.o util.o dvb.o udp.o asi.o demux.o output.o en50221.o comm.o mrtg-cnt.o asi-deltacast.o $(OBJ_DVBCSA) $(OBJ_WEB)
OBJ_DVBLASTCTL = util.o dvblastctl.o

ifndef V
Q = @
endif

CLEAN_OBJS = dvblast dvblastctl $(OBJ_DVBLAST) $(OBJ_DVBLASTCTL) dvbcsa/*.o *.d modules/*/*.d
INSTALL_BIN = dvblast dvblastctl dvblast_mmi.sh
INSTALL_MAN = dvblast.1

PREFIX ?= /usr/local
BIN = $(subst //,/,$(DESTDIR)/$(PREFIX)/bin)
MAN = $(subst //,/,$(DESTDIR)/$(PREFIX)/share/man/man1)

all: dvblast dvblastctl

.PHONY: clean install uninstall dist

web_ui_embed.c: web/dvblast_ui.html
	@echo "GEN     $@"
	@python3 -c 'data = open("web/dvblast_ui.html", "rb").read(); out = open("web_ui_embed.c", "w"); out.write("/* Generated automatically from web/dvblast_ui.html */\n#include \"web_ui_embed.h\"\n\nconst unsigned char web_ui_html[] = {\n"); [out.write("    " + ", ".join(f"0x{b:02x}" for b in data[i:i+16]) + ",\n") for i in range(0, len(data), 16)]; out.write("    0x00\n};\n\nconst size_t web_ui_html_len = %d;\n" % len(data)); out.close()'

%.o: %.c
	@echo "CC      $<"
	$(Q)$(CROSS)$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

dvblast: $(OBJ_DVBLAST)
	@echo "LINK    $@"
	$(Q)$(CROSS)$(CC) $(LDFLAGS) -o $@ $(OBJ_DVBLAST) $(LDLIBS_DVBLAST) $(LDLIBS)

dvblastctl: $(OBJ_DVBLASTCTL)
	@echo "LINK    $@"
	$(Q)$(CROSS)$(CC) $(LDFLAGS) -o $@ $(OBJ_DVBLASTCTL) $(LDLIBS)

clean:
	@echo "CLEAN   $(CLEAN_OBJS)"
	$(Q)rm -f $(CLEAN_OBJS)

distclean: clean

install: all
	@install -d "$(BIN)"
	@install -d "$(MAN)"
	@echo "INSTALL $(INSTALL_MAN) -> $(MAN)"
	$(Q)install -m 644 dvblast.1 "$(MAN)"
	@echo "INSTALL $(INSTALL_BIN) -> $(BIN)"
	$(Q)install dvblast dvblastctl dvblast_mmi.sh "$(BIN)"

uninstall:
	@-for FILE in $(INSTALL_BIN); do \
		echo "RM       $(BIN)/$$FILE"; \
		rm "$(BIN)/$$FILE"; \
	done
	@-for FILE in $(INSTALL_MAN); do \
		echo "RM       $(MAN)/$$FILE"; \
		rm "$(MAN)/$$FILE"; \
	done

dist: clean
	@echo "ARCHIVE dvblast-$(VERSION_MAJOR).$(VERSION_MINOR).tar.bz2"
	$(Q)git archive --format=tar --prefix=dvblast-$(VERSION_MAJOR).$(VERSION_MINOR)/ master | bzip2 -9 > dvblast-$(VERSION_MAJOR).$(VERSION_MINOR).tar.bz2
	$(Q)ls -l dvblast-$(VERSION_MAJOR).$(VERSION_MINOR).tar.bz2

-include $(OBJ_DVBLAST:.o=.d) $(OBJ_DVBLASTCTL:.o=.d)


