//===-- CommandObjectQuit.cpp ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "CommandObjectC3.h"

#include "c3/c3_llvm.h"

#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Interpreter/OptionArgParser.h"
#include "lldb/Target/Process.h"
#include "lldb/Utility/LLDBAssert.h"
#include "lldb/Utility/StreamString.h"

using namespace lldb;
using namespace lldb_private;

class CommandObjectC3Keys : public CommandObjectParsed {
public:
  CommandObjectC3Keys(CommandInterpreter &interpreter)
      : CommandObjectParsed(
            interpreter, "c3 keys", "C3 key management", nullptr,
            eCommandRequiresTarget | eCommandProcessMustBePaused) {

    CommandArgumentEntry arg1;

    CommandArgumentData cmd_arg;
    cmd_arg.arg_type = eArgTypeName;
    cmd_arg.arg_repetition = eArgRepeatPlain;
    arg1.push_back(cmd_arg);

    m_arguments.push_back(arg1);
  }

  bool DoExecute(Args &command, CommandReturnObject &result) override {
    Target *target = &GetSelectedTarget();
    ProcessSP process_sp = target->GetProcessSP();
    lldbassert(process_sp != nullptr);

    const size_t argc = command.GetArgumentCount();
    if (argc == 0 || argc > 2) {
      result.AppendErrorWithFormat("%s takes 1-2 argument.\n", m_cmd_name.c_str());
      return false;
    }

    const char *cmd_arg = command.GetArgumentAtIndex(0);

    if (strcmp(cmd_arg, "dump") == 0) {
      process_sp->c3_dump_keys();

      result.AppendMessageWithFormat(
          "%-10s: %s\n", "data key",
          buf_to_hex_string(process_sp->c3_get_data_key(), c3_data_key_size)
              .c_str());
      result.AppendMessageWithFormat(
          "%-10s: %s\n", "ptr key",
          buf_to_hex_string(process_sp->c3_get_ptr_key(), c3_ptr_key_size)
              .c_str());
      return true;
    }

    if (strcmp(cmd_arg, "data_key") == 0) {
      lldbassert(argc == 2);
      const size_t key_buf_size = c3_data_key_size;
      uint8_t key_buf[key_buf_size];

      auto arg = command.GetArgumentAtIndex(1);
      lldbassert(key_buf_size * 2 == strlen(arg));

      string_to_hex_buf(key_buf, arg, key_buf_size * 2);
      process_sp->c3_set_data_key(key_buf);

      result.AppendMessageWithFormat(
          "C3 data key set to: 0x%s\n",
          buf_to_hex_string(key_buf, key_buf_size).c_str());
      return true;
    }

    if (strcmp(cmd_arg, "ptr_key") == 0) {
      lldbassert(argc == 2);
      const size_t key_buf_size = c3_ptr_key_size;
      uint8_t key_buf[key_buf_size];

      auto arg = command.GetArgumentAtIndex(1);
      lldbassert(key_buf_size * 2 == strlen(arg));

      string_to_hex_buf(key_buf, arg, key_buf_size * 2);
      process_sp->c3_set_ptr_key(key_buf);

      result.AppendMessageWithFormat(
          "C3 pointer key set to: 0x%s\n",
          buf_to_hex_string(key_buf, key_buf_size).c_str());
      return true;
    }

    result.AppendErrorWithFormat("%s, unknown command: %s\n", m_cmd_name.c_str(), cmd_arg);
    return false;
  }
};

class CommandObjectC3CAs : public CommandObjectParsed {
public:
  CommandObjectC3CAs(CommandInterpreter &interpreter)
      : CommandObjectParsed(
            interpreter, "c3 pointer", "C3 pointer encoding / decoding",
            nullptr, eCommandRequiresTarget | eCommandProcessMustBePaused) {

    CommandArgumentEntry arg1;

    CommandArgumentData cmd_arg;
    cmd_arg.arg_type = eArgTypeName;
    cmd_arg.arg_repetition = eArgRepeatPlain;
    arg1.push_back(cmd_arg);

    CommandArgumentEntry arg2;
    // CommandArgumentEntry arg2;

    CommandArgumentData start_addr_arg;
    CommandArgumentData end_addr_arg;

    start_addr_arg.arg_type = eArgTypeAddressOrExpression;
    start_addr_arg.arg_repetition = eArgRepeatPlain;

    // start_addr_arg.arg_type = eArgTypeAddressOrExpression;
    // start_addr_arg.arg_repetition = eArgRepeatOptional;

    // arg2

    m_arguments.push_back(arg1);
    m_arguments.push_back(arg2);
  }

  bool DoExecute(Args &command, CommandReturnObject &result) override {
    Target *target = &GetSelectedTarget();
    ProcessSP process_sp = target->GetProcessSP();

    const size_t argc = command.GetArgumentCount();
    if (argc == 0 || argc > 2) {
      result.AppendErrorWithFormat("%s takes 1-2 argument.\n", m_cmd_name.c_str());
      return false;
    }

    const char *cmd_arg = command.GetArgumentAtIndex(0);

    if (strcmp(cmd_arg, "decode") == 0) {
      if (argc != 2) {
        result.AppendError("Bad args");
        return false;
      }
      const char *ptr_arg = command.GetArgumentAtIndex(1);

      Status error;
      lldb::addr_t addr = OptionArgParser::ToAddress(
          &m_exe_ctx, ptr_arg, LLDB_INVALID_ADDRESS, &error);
      if (addr == LLDB_INVALID_ADDRESS) {
        result.AppendErrorWithFormat("invalid address: %s", ptr_arg);
        result.AppendError(error.AsCString());
        return false;
      }

      uint64_t ca = (uint64_t)addr;
      uint64_t la = process_sp->c3_decode_ptr(ca);

      result.AppendMessageWithFormat("decode_ptr: 0x%016lx -> 0x%016lx\n", ca,
                                     la);
      return true;
    }

    // TODO: Need to add extra parameter for size metadata
    // if (strcmp(cmd_arg == "encode")) {
    //   uint64_t la = m_next_addr;
    //   uint64_t ca = process_sp->c3_encode_ptr(la);
    //   result.GetOutputStream().Printf("encode_ptr: 0x%016lx -> 0x%016lx\n", la, ca);
    // }

    result.AppendErrorWithFormat("%s, unknown command: %s\n", m_cmd_name.c_str(), cmd_arg);
    return false;
  }
};

CommandObjectC3::CommandObjectC3(CommandInterpreter &interpreter)
    : CommandObjectMultiword(interpreter, "cc", "c3 commands.", "c3 stuff") {
  LoadSubCommand("keys", CommandObjectSP(new CommandObjectC3Keys(interpreter)));
  LoadSubCommand("pointer",
                 CommandObjectSP(new CommandObjectC3CAs(interpreter)));
}

CommandObjectC3::~CommandObjectC3() = default;
