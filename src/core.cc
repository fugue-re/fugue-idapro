#include <auto.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <gdl.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <segregs.hpp>
#include <xref.hpp>

#include <optional>
#include <map>
#include <set>
#include <sstream>

#include <fugue_common.h>
#include <fugue_ida.h>
#include <ida_helper.h>

namespace fugue
{
  namespace ida
  {

    using ProjectBuilder = ::fugue::ProjectBuilder<fugue::ida::Architecture>;

    void make_architecture(ProjectBuilder &builder, ea_t at = BADADDR)
    {
      builder.architecture(std::move(Architecture(at)));
    }

    std::optional<std::string> make_format()
    {
      switch (inf_get_filetype())
      {
      case f_BIN:
        return "Raw";
      case f_PE:
        return "PE";
      case f_ELF:
        return "ELF";
      case f_MACHO:
        return "Mach-O";
      default:
        return std::nullopt;
      }
    }

    void make_functions(ProjectBuilder &builder)
    {
      builder.reserve_functions(get_func_qty());
      for (auto fun_num = 0; fun_num != get_func_qty(); ++fun_num)
      {
        auto function = getn_func(fun_num);
        auto function_id = Id<Function>(fun_num);
        auto segment_id = get_segm_num(function->start_ea);

        auto name = qstring();
        get_func_name(&name, function->start_ea);

        if (function->flags & FUNC_THUNK)
        {
          if (auto target = calc_thunk_func_target(function, nullptr); target != BADADDR)
          {
            auto new_name = qstring();
            get_func_name(&new_name, target);
            if (!new_name.empty() && std::size(new_name) <= std::size(name))
            {
              name = new_name;
            }
          }
        }

        auto offset = function->start_ea;
#if IDA_SDK_VERSION < 750
        auto fc_options = FC_NOEXT | FC_PREDS;
#else
        auto fc_options = FC_NOEXT;
#endif
        auto graph = qflow_chart_t(
            nullptr,
            function,
            BADADDR,
            BADADDR,
            fc_options);

        auto entry = graph.empty() ? Id<BasicBlock>() : Id<BasicBlock>(function_id, graph.entry());
        auto xr = xrefblk_t();
        auto ref_count = 0;
        for (auto ok = xr.first_to(offset, XREF_ALL); ok; ok = xr.next_to())
        {
          if (!xr.iscode)
            continue;

          auto owning_func = get_func(xr.from);
          if (is_func_tail(owning_func))
          {
            auto owning_iter = func_parent_iterator_t(owning_func);
            for (auto okk = owning_iter.first(); okk; okk = owning_iter.next())
              ref_count++;
          }
          else
          {
            ref_count++;
          }
        }

        builder.reserve_function_refs(ref_count);
        builder.reserve_function_blocks(std::size(graph));

        for (auto block_idx = 0; block_idx != std::size(graph); ++block_idx)
        {
          auto const &block = graph.blocks[block_idx];

          auto blk_id = Id<BasicBlock>(function_id, block_idx);
          auto offset = block.start_ea;
          auto length = block.end_ea - block.start_ea;

          builder.reserve_block_preds(std::size(block.pred));
          builder.reserve_block_succs(std::size(block.succ));

          size_t idx = 0;
          for (auto const &pred_id : block.pred)
          {
            auto id = Id<BasicBlock>(function_id, pred_id);
            builder.set_block_pred(function_id, blk_id, idx++, id);
          }

          idx = 0;
          for (auto const &succ_id : block.succ)
          {
            auto id = Id<BasicBlock>(function_id, succ_id);
            builder.set_block_succ(function_id, blk_id, idx++, id);
          }

          builder.set_block(
              blk_id,
              offset,
              length,
              builder.architecture(Architecture(offset)));
        }

        size_t ref_id = 0;
        for (auto ok = xr.first_to(offset, XREF_ALL); ok; ok = xr.next_to())
        {
          if (!xr.iscode)
            continue;

          auto owning_func = get_func(xr.from);
          if (is_func_tail(owning_func))
          {
            auto owning_iter = func_parent_iterator_t(owning_func);
            for (auto okk = owning_iter.first(); okk; okk = owning_iter.next())
            {
              // expand to all parent functions
              auto parent = owning_iter.parent();
              auto id = Id<Function>(get_func_num(parent));

              builder.set_function_ref(
                  function_id,
                  ref_id++,
                  xr.from,
                  id,
                  xr.type == cref_t::fl_CF || xr.type == cref_t::fl_CN);
            }
            continue;
          }

          builder.set_function_ref(
              function_id,
              ref_id++,
              xr.from,
              owning_func == nullptr ? Id<Function>() : Id<Function>(get_func_num(xr.from)),
              xr.type == cref_t::fl_CF || xr.type == cref_t::fl_CN);
        }

        builder.set_function(function_id, std::string(name.c_str()), offset, entry);
      }
    }

    void make_segments(ProjectBuilder &builder)
    {
      auto amount = get_segm_qty();
      builder.reserve_segments(amount);

      for (auto seg_num = 0; seg_num != get_segm_qty(); ++seg_num)
      {
        auto id = Id<Segment>(seg_num);
        auto segment = getnseg(seg_num);

        auto name = qstring();
        get_segm_name(&name, segment);

        auto executable = (SEGPERM_EXEC & segment->perm) != 0;
        auto readable = (SEGPERM_READ & segment->perm) != 0;
        auto writable = (SEGPERM_WRITE & segment->perm) != 0;

        auto address_size = segment->abits();
        auto alignment = 1;
        switch (segment->align)
        {
        case saRelByte:
          alignment = 1;
          break;
        case saRelWord:
          alignment = 2;
          break;
        case saRelDble:
          alignment = 4;
          break;
        case saRelQword:
          alignment = 8;
          break;
        case saRelPara:
          alignment = 16;
          break;
        case saRel32Bytes:
          alignment = 32;
          break;
        case saRel64Bytes:
          alignment = 64;
          break;
        case saRel128Bytes:
          alignment = 128;
          break;
        case saRel512Bytes:
          alignment = 512;
          break;
        case saRel1024Bytes:
          alignment = 1024;
          break;
        case saRel2048Bytes:
          alignment = 2048;
          break;
        default:
          alignment = 1;
        }

        auto code = (SEG_CODE & segment->type) != 0;
        auto data = (SEG_DATA & segment->type) != 0;
        auto xtrn = (SEG_XTRN & segment->type) != 0;

        auto bits = 16;
        if (segment->bitness == 2) {
          bits = 64;
        } else if (segment->bitness == 1) {
          bits = 32;
        }

        auto offset = segment->start_ea;
        auto length = segment->end_ea - segment->start_ea;

        auto content = builder.reserve_segment_bytes(length);
        get_bytes(content, length, offset, GMB_READALL);

        builder.set_segment(
            id,
            std::string(name.c_str()),
            offset,
            length,
            address_size,
            alignment,
            bits,
            inf_is_be(), // NOTE: IDA doesn't set byte order on segments
            code,
            data,
            xtrn,
            readable,
            writable,
            executable);
      }
    }

    int import(std::string const &output)
    {
      fugue::start_timestamp = current_timestamp();

      auto_wait(); // wait until analysis has finished

      auto builder = ProjectBuilder();

      auto format = make_format();
      if (!format.has_value())
      {
        return EXIT_UNSUPPORTED_ERROR;
      }

      auto exporter = "IDA Pro v" + ida_version();

      builder.set_metadata(
          *format,
          input_file_path(),
          input_file_md5(),
          input_file_sha256(),
          input_file_size(),
          exporter);

      make_architecture(builder);
      make_segments(builder);
      make_functions(builder);

      auto success = builder.write_to_file(output);

      if (!success)
      {
        msg("Fugue IDB exporter: failed to write database to file\n");
        return EXIT_IO_ERROR;
      }

      auto stats = std::stringstream();
      stats << "Fugue IDB exporter: successful export:" << std::endl;
      stats << "- Segments: " << builder.segment_count() << std::endl;
      stats << "- Functions: " << builder.function_count() << std::endl;

      msg("%s", stats.str().c_str());

      return EXIT_OK;
    }

    ssize_t idaapi ui_hook(void *, int event_id, va_list arguments)
    {
      if (event_id != ui_ready_to_run)
      {
        return 0;
      }

      auto path = get_argument("Output");
      if (path.empty())
      {
        return 0;
      }

      set_database_flag(DBFL_KILL);

      if (file_exists(path.c_str()) && !opt_true(get_argument("ForceOverwrite")))
      {
        qexit(EXIT_IO_ERROR);
      }

      auto rebase = get_argument("Rebase");
      if (!rebase.empty()) {
        auto is_relative = rebase[0] == '+' || rebase[0] == '-';

        ea_t rebase_value = 0;
        adiff_t rebase_diff = 0;

        if (!atoea(&rebase_value, rebase.c_str())) {
          qexit(EXIT_REBASE_ERROR);
        };

        if (!is_relative) {
          ea_t base = get_imagebase();
          rebase_diff = rebase_value - base;
        } else {
          rebase_diff = rebase_value;
          if (rebase[0] == '-') {
            rebase_diff = -rebase_diff;
          }
        }

        auto_wait(); // ensure analysis queues are clear
        if (rebase_program(rebase_diff, MSF_FIXONCE | MSF_SILENT | MSF_PRIORITY) != MOVE_SEGM_OK) {
          qexit(EXIT_REBASE_ERROR);
        }
      }

      auto success = import(path);

      qexit(success);

      return 0; // unreachable
    }

    plugin_init_t idaapi init()
    {
      if (!hook_to_notification_point(HT_UI, ui_hook, nullptr))
      {
        msg("Fugue IDB exporter: hook_to_notification_point() failed\n");
        return PLUGIN_SKIP;
      }
      return PLUGIN_KEEP;
    }

    bool idaapi run(size_t /*arg*/)
    {
      auto path = ask_file(true, nullptr, "FILTER Fugue database|*.fdb\nExport to Fugue database");
      if (!path)
      {
        return false;
      }

      if (file_exists(path) && ask_yn(0, "`%s` already exists; overwrite it?", path) != 1)
      {
        return false;
      }

      auto success = EXIT_OK;
      try
      {
        show_wait_box("HIDECANCEL\nExporting to Fugue database...");
        success = import(std::string(path));
        if (success != EXIT_OK)
        {
          ask_form("STARTITEM 0\nBUTTON YES OK\nBUTTON CANCEL NONE\nFugue IDB exporter\nExport to database failed\n");
        }
      }
      catch (std::exception &ex)
      {
        auto message = std::string("STARTITEM 0\nBUTTON YES OK\nBUTTON CANCEL NONE\nFugue IDB exporter\nExport failed with error:\n") + ex.what() + "\n";
        ask_form(message.c_str());
      }

      hide_wait_box();

      return success == EXIT_OK;
    }

    void idaapi term()
    {
      unhook_from_notification_point(HT_UI, ui_hook, nullptr);
    }

  }; // namespace ida
};   // namespace fugue

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX,
    fugue::ida::init,
    fugue::ida::term,
    fugue::ida::run,
    "Fugue IDB exporter",
    nullptr,
    "Export to Fugue FDB database",
    "Alt+F10",
};
