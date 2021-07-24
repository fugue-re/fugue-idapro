include ../../allmake.mak

SCRIPTS += ebc.py
SCRIPTS += msp430.py

BIN_PATH = $(R)procs/
all: $(addprefix $(BIN_PATH),$(SCRIPTS))

$(BIN_PATH)%: %
	$(CP) $? $@
