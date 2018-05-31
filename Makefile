.PHONY: clean help .depend

EXE = sandbox
SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)
DEPS = $(OBJECTS:.o=.d)

CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -std=c11 -g
CPPFLAGS = -I./includes -MD -MP
LDFLAGS =

all: $(EXE)

$(EXE): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(DEPS) $(EXE)
	find . -name "*~" -delete

help:
	@echo "make          Build $(EXE)"
	@echo "make deps     Generate .depends"
	@echo "make clean    Delete compilation files"
	@echo "make help     Print this help message"

-include $(DEPS)
