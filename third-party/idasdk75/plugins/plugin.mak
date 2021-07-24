
#__FUZZ_PLUGINS__=1

SRC_PATH = $(IDA)plugins/
ifdef EXAMPLE
  BIN_PATH = $(R)plugins-examples/
else
  BIN_PATH = $(R)plugins/
endif

ifndef NO_DEFAULT_TARGETS
  BASE_OBJS += $(F)$(PROC)$(O)
endif

include ../../module.mak

ifdef __NT__
  ifndef NDEBUG
    $(MODULES): PDBFLAGS = /PDB:$(@:$(DLLEXT)=.pdb)
  endif
endif
