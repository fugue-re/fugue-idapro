
# definitions for idapython (& other plugins dynamically linked to Python)
ifdef __NT__
  PYTHON_CFLAGS  := -I"$(PYTHON_ROOT)/include"
  ifeq ($(PYTHON_VERSION_MAJOR),3)
    PYTHON_LDFLAGS := "$(PYTHON_ROOT)/libs/python$(PYTHON_VERSION_MAJOR).lib"
  else
    PYTHON_LDFLAGS := "$(PYTHON_ROOT)/libs/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR).lib"
  endif
else
  PYTHON_CFLAGS  := $(shell $(PYTHON)-config --includes)
  PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags)
endif
