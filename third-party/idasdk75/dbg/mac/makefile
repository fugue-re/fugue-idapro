include ../../allmake.mak

GOALS-$(BUILD_IDA) += configs # target in $(IDA)module.mak
GOALS-$(BUILD_IDA) += modules # target in $(IDA)module.mak
GOALS-$(BUILD_DBGSRV) += server # target in $(IDA)dbg/server.mak
.PHONY: $(GOALS-1)
all: $(GOALS-1)

#----------------------------------------------------------------------
ifdef __MAC__
  SERVER = mac_server$(B)
endif
ifdef SERVER
  SERVERS += $(call server_exe,$(SERVER))
endif

#----------------------------------------------------------------------
STUB = $(call module_dll,mac_stub)
ifdef BUILD_IDA
  MODULES += $(STUB)
endif

#----------------------------------------------------------------------
USER = $(call module_dll,mac_user)
ifeq ($(and $(BUILD_IDA),$(__MAC__)),1)
  MODULES += $(USER)
  CONFIGS += dbg_macosx.cfg
endif

#----------------------------------------------------------------------
# we explicitly added our module targets
NO_DEFAULT_TARGETS = 1

# NOTE: all MODULES must be defined before including plugin.mak.
include ../plugin.mak
# NOTE: target-specific rules and dependencies that use variable
#       expansion to name the target (such as "$(MODULE): [...]") must
#       come after including plugin.mak

#----------------------------------------------------------------------
# select OBJS common to user plugin and debugger server
BASE_OBJS-$(__MAC__) += $(F)macbase_debmod$(O)
BASE_OBJS-$(__MAC__) += $(F)mac_debmod$(O)
BASE_OBJS-$(__MAC__) += $(F)excServer$(O)

BASE_OBJS += $(BASE_OBJS-1) $(F)symmacho$(O)

$(F)symmacho$(O): CC_INCP += ../../ldr/mach-o/h $(IRRXML)
$(F)mac_debmod$(O): CC_INCP += ../../ldr/mach-o/h

excServer.c:
	mig $(MACSDK)/usr/include/mach/exc.defs
ifdef __LINT__
$(F)excServer$(O):
	touch $@
endif

#----------------------------------------------------------------------
SERVER_LDFLAGS += $(OUTMAP)$(F)$(@F).map
SERVER_LDFLAGS += -Wl,-sectcreate,__TEXT,__info_plist,mac_debug$(B).plist

SERVER_STDLIBS += -framework CoreFoundation
SERVER_STDLIBS += -framework Security

# NOTE: perform the steps in mac_server_certificate.txt before using CODESIGN_MAC_SERVER!
ifdef CODESIGN_MAC_SERVER
  CODESIGN_IDENTITY ?= mac_server
  ifdef MAC_KEYCHAIN
    CODESIGN_OPTS = --keychain $(MAC_KEYCHAIN).keychain
  endif
  ifdef MAC_TIMESTAMP
    CODESIGN_OPTS += --timestamp=$(MAC_TIMESTAMP)
  endif
  ifndef __CODE_CHECKER__
    SERVER_POSTACTION = $(strip codesign $(CODESIGN_OPTS) -s "$(CODESIGN_IDENTITY)" $@)
  endif
endif
SERVER_OBJS += $(BASE_OBJS)

include ../server.mak

#----------------------------------------------------------------------
STUB_OBJS += $(F)mac_stub$(O)
STUB_OBJS += $(F)symmacho$(O)
$(STUB): MODULE_OBJS += $(STUB_OBJS)
$(STUB): $(STUB_OBJS)

#----------------------------------------------------------------------
USER_OBJS += $(F)mac_user$(O)
USER_OBJS += $(BASE_OBJS)
$(USER): MODULE_OBJS += $(USER_OBJS)
$(USER): $(USER_OBJS)
$(USER): STDLIBS += -framework Security
$(USER): STDLIBS += -framework CoreFoundation

#----------------------------------------------------------------------
include $(IDA)objdir.mak

# MAKEDEP dependency list ------------------
$(F)excServer$(O): ../../ldr/mach-o/h/arm/_types.h                          \
                  ../../ldr/mach-o/h/i386/_types.h                          \
                  ../../ldr/mach-o/h/mach/arm/boolean.h                     \
                  ../../ldr/mach-o/h/mach/arm/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/boolean.h                         \
                  ../../ldr/mach-o/h/mach/i386/boolean.h                    \
                  ../../ldr/mach-o/h/mach/i386/kern_return.h                \
                  ../../ldr/mach-o/h/mach/i386/vm_param.h                   \
                  ../../ldr/mach-o/h/mach/i386/vm_types.h                   \
                  ../../ldr/mach-o/h/mach/kern_return.h                     \
                  ../../ldr/mach-o/h/mach/machine/boolean.h                 \
                  ../../ldr/mach-o/h/mach/machine/kern_return.h             \
                  ../../ldr/mach-o/h/mach/machine/vm_types.h                \
                  ../../ldr/mach-o/h/mach/message.h                         \
                  ../../ldr/mach-o/h/mach/port.h                            \
                  ../../ldr/mach-o/h/mach/ppc/boolean.h                     \
                  ../../ldr/mach-o/h/mach/ppc/kern_return.h                 \
                  ../../ldr/mach-o/h/mach/ppc/vm_param.h                    \
                  ../../ldr/mach-o/h/mach/ppc/vm_types.h                    \
                  ../../ldr/mach-o/h/ppc/_types.h                           \
                  ../../ldr/mach-o/h/sys/_posix_availability.h              \
                  ../../ldr/mach-o/h/sys/_symbol_aliasing.h                 \
                  ../../ldr/mach-o/h/sys/cdefs.h excServer.c
$(F)mac_debmod$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp           \
                  $(I)diskio.hpp $(I)err.h $(I)fpro.h $(I)funcs.hpp         \
                  $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)name.hpp $(I)netnode.hpp $(I)network.hpp $(I)pro.h    \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  ../../ldr/mach-o/common.h                                 \
                  ../../ldr/mach-o/h/architecture/byte_order.h              \
                  ../../ldr/mach-o/h/arm/_types.h                           \
                  ../../ldr/mach-o/h/i386/_types.h                          \
                  ../../ldr/mach-o/h/i386/eflags.h                          \
                  ../../ldr/mach-o/h/libkern/OSByteOrder.h                  \
                  ../../ldr/mach-o/h/libkern/i386/OSByteOrder.h             \
                  ../../ldr/mach-o/h/libkern/i386/_OSByteOrder.h            \
                  ../../ldr/mach-o/h/libkern/machine/OSByteOrder.h          \
                  ../../ldr/mach-o/h/mach-o/arm/reloc.h                     \
                  ../../ldr/mach-o/h/mach-o/arm64/reloc.h                   \
                  ../../ldr/mach-o/h/mach-o/fat.h                           \
                  ../../ldr/mach-o/h/mach-o/hppa/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/i860/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/loader.h                        \
                  ../../ldr/mach-o/h/mach-o/m88k/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/nlist.h                         \
                  ../../ldr/mach-o/h/mach-o/ppc/reloc.h                     \
                  ../../ldr/mach-o/h/mach-o/reloc.h                         \
                  ../../ldr/mach-o/h/mach-o/sparc/reloc.h                   \
                  ../../ldr/mach-o/h/mach-o/stab.h                          \
                  ../../ldr/mach-o/h/mach-o/x86_64/reloc.h                  \
                  ../../ldr/mach-o/h/mach/arm/_structs.h                    \
                  ../../ldr/mach-o/h/mach/arm/boolean.h                     \
                  ../../ldr/mach-o/h/mach/arm/thread_state.h                \
                  ../../ldr/mach-o/h/mach/arm/thread_status.h               \
                  ../../ldr/mach-o/h/mach/arm/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/boolean.h                         \
                  ../../ldr/mach-o/h/mach/i386/_structs.h                   \
                  ../../ldr/mach-o/h/mach/i386/boolean.h                    \
                  ../../ldr/mach-o/h/mach/i386/fp_reg.h                     \
                  ../../ldr/mach-o/h/mach/i386/kern_return.h                \
                  ../../ldr/mach-o/h/mach/i386/thread_state.h               \
                  ../../ldr/mach-o/h/mach/i386/thread_status.h              \
                  ../../ldr/mach-o/h/mach/i386/vm_param.h                   \
                  ../../ldr/mach-o/h/mach/i386/vm_types.h                   \
                  ../../ldr/mach-o/h/mach/kern_return.h                     \
                  ../../ldr/mach-o/h/mach/machine.h                         \
                  ../../ldr/mach-o/h/mach/machine/boolean.h                 \
                  ../../ldr/mach-o/h/mach/machine/kern_return.h             \
                  ../../ldr/mach-o/h/mach/machine/thread_status.h           \
                  ../../ldr/mach-o/h/mach/machine/vm_types.h                \
                  ../../ldr/mach-o/h/mach/message.h                         \
                  ../../ldr/mach-o/h/mach/port.h                            \
                  ../../ldr/mach-o/h/mach/ppc/_structs.h                    \
                  ../../ldr/mach-o/h/mach/ppc/boolean.h                     \
                  ../../ldr/mach-o/h/mach/ppc/kern_return.h                 \
                  ../../ldr/mach-o/h/mach/ppc/thread_status.h               \
                  ../../ldr/mach-o/h/mach/ppc/vm_param.h                    \
                  ../../ldr/mach-o/h/mach/ppc/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/shared_region.h                   \
                  ../../ldr/mach-o/h/mach/vm_prot.h                         \
                  ../../ldr/mach-o/h/mach/vm_types.h                        \
                  ../../ldr/mach-o/h/ppc/_types.h                           \
                  ../../ldr/mach-o/h/sys/_posix_availability.h              \
                  ../../ldr/mach-o/h/sys/_symbol_aliasing.h                 \
                  ../../ldr/mach-o/h/sys/appleapiopts.h                     \
                  ../../ldr/mach-o/h/sys/cdefs.h                            \
                  ../../ldr/mach-o/h/sys/ptrace.h                           \
                  ../../ldr/mach-o/macho_node.h ../deb_pc.hpp ../debmod.h   \
                  ../pc_debmod.h ../pc_regs.hpp mac_debmod.cpp              \
                  mac_debmod.h macbase_debmod.h symmacho.hpp
$(F)mac_stub$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)dbg.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h             \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
                  $(I)network.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../../ldr/mach-o/macho_node.h ../common_local_impl.cpp    \
                  ../common_stub_impl.cpp ../dbg_rpc_client.h               \
                  ../dbg_rpc_engine.h ../deb_pc.hpp ../debmod.h             \
                  ../macho_rebase.cpp ../pc_local_impl.cpp ../pc_regs.hpp   \
                  ../rpc_debmod.h mac_local_impl.cpp mac_stub.cpp           \
                  symmacho.hpp
$(F)mac_user$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)dbg.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp         \
                  $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp          \
                  $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
                  $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
                  $(I)network.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../../ldr/mach-o/h/architecture/byte_order.h              \
                  ../../ldr/mach-o/h/arm/_types.h                           \
                  ../../ldr/mach-o/h/i386/_types.h                          \
                  ../../ldr/mach-o/h/libkern/OSByteOrder.h                  \
                  ../../ldr/mach-o/h/libkern/i386/OSByteOrder.h             \
                  ../../ldr/mach-o/h/libkern/i386/_OSByteOrder.h            \
                  ../../ldr/mach-o/h/libkern/machine/OSByteOrder.h          \
                  ../../ldr/mach-o/h/mach-o/fat.h                           \
                  ../../ldr/mach-o/h/mach-o/nlist.h                         \
                  ../../ldr/mach-o/h/mach-o/reloc.h                         \
                  ../../ldr/mach-o/h/mach/arm/boolean.h                     \
                  ../../ldr/mach-o/h/mach/arm/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/boolean.h                         \
                  ../../ldr/mach-o/h/mach/i386/boolean.h                    \
                  ../../ldr/mach-o/h/mach/i386/vm_param.h                   \
                  ../../ldr/mach-o/h/mach/i386/vm_types.h                   \
                  ../../ldr/mach-o/h/mach/machine.h                         \
                  ../../ldr/mach-o/h/mach/machine/boolean.h                 \
                  ../../ldr/mach-o/h/mach/machine/vm_types.h                \
                  ../../ldr/mach-o/h/mach/port.h                            \
                  ../../ldr/mach-o/h/mach/ppc/boolean.h                     \
                  ../../ldr/mach-o/h/mach/ppc/vm_param.h                    \
                  ../../ldr/mach-o/h/mach/ppc/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/shared_region.h                   \
                  ../../ldr/mach-o/h/mach/vm_prot.h                         \
                  ../../ldr/mach-o/h/mach/vm_types.h                        \
                  ../../ldr/mach-o/h/ppc/_types.h                           \
                  ../../ldr/mach-o/h/sys/_posix_availability.h              \
                  ../../ldr/mach-o/h/sys/_symbol_aliasing.h                 \
                  ../../ldr/mach-o/h/sys/appleapiopts.h                     \
                  ../../ldr/mach-o/h/sys/cdefs.h                            \
                  ../../ldr/mach-o/h/sys/ptrace.h                           \
                  ../../ldr/mach-o/macho_node.h ../common_local_impl.cpp    \
                  ../common_stub_impl.cpp ../deb_pc.hpp ../debmod.h         \
                  ../macho_rebase.cpp ../pc_debmod.h ../pc_local_impl.cpp   \
                  ../pc_regs.hpp mac_debmod.h mac_local_impl.cpp            \
                  mac_user.cpp macbase_debmod.h symmacho.hpp
$(F)macbase_debmod$(O): $(I)bytes.hpp $(I)diskio.hpp $(I)fpro.h             \
                  $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp $(I)lines.hpp     \
                  $(I)llong.hpp $(I)nalt.hpp $(I)netnode.hpp                \
                  $(I)network.hpp $(I)pro.h $(I)prodir.h $(I)range.hpp      \
                  $(I)ua.hpp $(I)xref.hpp                                   \
                  ../../ldr/mach-o/h/architecture/byte_order.h              \
                  ../../ldr/mach-o/h/arm/_types.h                           \
                  ../../ldr/mach-o/h/i386/_types.h                          \
                  ../../ldr/mach-o/h/libkern/OSByteOrder.h                  \
                  ../../ldr/mach-o/h/libkern/i386/OSByteOrder.h             \
                  ../../ldr/mach-o/h/libkern/i386/_OSByteOrder.h            \
                  ../../ldr/mach-o/h/libkern/machine/OSByteOrder.h          \
                  ../../ldr/mach-o/h/mach-o/fat.h                           \
                  ../../ldr/mach-o/h/mach/arm/boolean.h                     \
                  ../../ldr/mach-o/h/mach/arm/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/boolean.h                         \
                  ../../ldr/mach-o/h/mach/i386/boolean.h                    \
                  ../../ldr/mach-o/h/mach/i386/vm_param.h                   \
                  ../../ldr/mach-o/h/mach/i386/vm_types.h                   \
                  ../../ldr/mach-o/h/mach/machine.h                         \
                  ../../ldr/mach-o/h/mach/machine/boolean.h                 \
                  ../../ldr/mach-o/h/mach/machine/vm_types.h                \
                  ../../ldr/mach-o/h/mach/ppc/boolean.h                     \
                  ../../ldr/mach-o/h/mach/ppc/vm_param.h                    \
                  ../../ldr/mach-o/h/mach/ppc/vm_types.h                    \
                  ../../ldr/mach-o/h/ppc/_types.h ../deb_pc.hpp             \
                  ../debmod.h ../pc_debmod.h ../pc_regs.hpp                 \
                  macbase_debmod.cpp macbase_debmod.h symmacho.hpp
$(F)symmacho$(O): $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diskio.hpp $(I)entry.hpp $(I)err.h     \
                  $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp                    \
                  $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)name.hpp $(I)netnode.hpp $(I)network.hpp              \
                  $(I)offset.hpp $(I)pro.h $(I)prodir.h $(I)range.hpp       \
                  $(I)segment.hpp $(I)segregs.hpp $(I)ua.hpp $(I)xref.hpp   \
                  $(IRRXML)CXMLReaderImpl.h $(IRRXML)fast_atof.h            \
                  $(IRRXML)heapsort.h $(IRRXML)irrArray.h                   \
                  $(IRRXML)irrString.h $(IRRXML)irrTypes.h                  \
                  $(IRRXML)irrXML.h ../../ldr/ar/aixar.hpp                  \
                  ../../ldr/ar/ar.hpp ../../ldr/ar/arcmn.cpp                \
                  ../../ldr/mach-o/../ar/ar.hpp                             \
                  ../../ldr/mach-o/../idaldr.h ../../ldr/mach-o/base.cpp    \
                  ../../ldr/mach-o/common.cpp ../../ldr/mach-o/common.h     \
                  ../../ldr/mach-o/dsym.cpp ../../ldr/mach-o/dsym.h         \
                  ../../ldr/mach-o/h/architecture/byte_order.h              \
                  ../../ldr/mach-o/h/arm/_types.h                           \
                  ../../ldr/mach-o/h/i386/_types.h                          \
                  ../../ldr/mach-o/h/i386/eflags.h                          \
                  ../../ldr/mach-o/h/libkern/OSByteOrder.h                  \
                  ../../ldr/mach-o/h/libkern/i386/OSByteOrder.h             \
                  ../../ldr/mach-o/h/libkern/i386/_OSByteOrder.h            \
                  ../../ldr/mach-o/h/libkern/machine/OSByteOrder.h          \
                  ../../ldr/mach-o/h/mach-o/arm/reloc.h                     \
                  ../../ldr/mach-o/h/mach-o/arm64/reloc.h                   \
                  ../../ldr/mach-o/h/mach-o/fat.h                           \
                  ../../ldr/mach-o/h/mach-o/hppa/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/i860/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/loader.h                        \
                  ../../ldr/mach-o/h/mach-o/m88k/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/nlist.h                         \
                  ../../ldr/mach-o/h/mach-o/ppc/reloc.h                     \
                  ../../ldr/mach-o/h/mach-o/reloc.h                         \
                  ../../ldr/mach-o/h/mach-o/sparc/reloc.h                   \
                  ../../ldr/mach-o/h/mach-o/stab.h                          \
                  ../../ldr/mach-o/h/mach-o/x86_64/reloc.h                  \
                  ../../ldr/mach-o/h/mach/arm/_structs.h                    \
                  ../../ldr/mach-o/h/mach/arm/boolean.h                     \
                  ../../ldr/mach-o/h/mach/arm/thread_state.h                \
                  ../../ldr/mach-o/h/mach/arm/thread_status.h               \
                  ../../ldr/mach-o/h/mach/arm/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/boolean.h                         \
                  ../../ldr/mach-o/h/mach/i386/_structs.h                   \
                  ../../ldr/mach-o/h/mach/i386/boolean.h                    \
                  ../../ldr/mach-o/h/mach/i386/fp_reg.h                     \
                  ../../ldr/mach-o/h/mach/i386/kern_return.h                \
                  ../../ldr/mach-o/h/mach/i386/thread_state.h               \
                  ../../ldr/mach-o/h/mach/i386/thread_status.h              \
                  ../../ldr/mach-o/h/mach/i386/vm_param.h                   \
                  ../../ldr/mach-o/h/mach/i386/vm_types.h                   \
                  ../../ldr/mach-o/h/mach/kern_return.h                     \
                  ../../ldr/mach-o/h/mach/kmod.h                            \
                  ../../ldr/mach-o/h/mach/machine.h                         \
                  ../../ldr/mach-o/h/mach/machine/boolean.h                 \
                  ../../ldr/mach-o/h/mach/machine/kern_return.h             \
                  ../../ldr/mach-o/h/mach/machine/thread_status.h           \
                  ../../ldr/mach-o/h/mach/machine/vm_types.h                \
                  ../../ldr/mach-o/h/mach/message.h                         \
                  ../../ldr/mach-o/h/mach/port.h                            \
                  ../../ldr/mach-o/h/mach/ppc/_structs.h                    \
                  ../../ldr/mach-o/h/mach/ppc/boolean.h                     \
                  ../../ldr/mach-o/h/mach/ppc/kern_return.h                 \
                  ../../ldr/mach-o/h/mach/ppc/thread_status.h               \
                  ../../ldr/mach-o/h/mach/ppc/vm_param.h                    \
                  ../../ldr/mach-o/h/mach/ppc/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/vm_prot.h                         \
                  ../../ldr/mach-o/h/mach/vm_types.h                        \
                  ../../ldr/mach-o/h/ppc/_types.h                           \
                  ../../ldr/mach-o/h/sys/_posix_availability.h              \
                  ../../ldr/mach-o/h/sys/_symbol_aliasing.h                 \
                  ../../ldr/mach-o/h/sys/cdefs.h                            \
                  ../../ldr/mach-o/macho_node.h ../debmod.h symmacho.cpp    \
                  symmacho.hpp
