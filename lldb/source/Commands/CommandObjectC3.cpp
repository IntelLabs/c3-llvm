//===-- CommandObjectC3.cpp -----------------------------------------------===//
//
// Copyright (C) 2023 Intel Corporation
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//

#include "CommandObjectC3.h"

#include "c3/llvm_c3_cc_globals.h"
#include "c3/hex_string.h"

#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Interpreter/OptionArgParser.h"
#include "lldb/Target/C3Support.h"
#include "lldb/Target/Process.h"
#include "lldb/Utility/LLDBAssert.h"
#include "lldb/Utility/StreamString.h"

#include <string>

using namespace lldb;
using namespace c3_lldb;
using namespace lldb_private;

class CommandObjectC3Keys : public CommandObjectParsed {
public:
  CommandObjectC3Keys(CommandInterpreter &interpreter)
      : CommandObjectParsed(interpreter, "c3 keys", "C3 key management",
                            "c3 keys [dump|data_key|ptr_key] [hex_key_string]",
                            eCommandRequiresTarget |
                                eCommandProcessMustBePaused) {

    CommandArgumentEntry arg1;

    CommandArgumentData cmd_arg;
    cmd_arg.arg_type = eArgTypeName;
    cmd_arg.arg_repetition = eArgRepeatPlain;
    arg1.push_back(cmd_arg);

    m_arguments.push_back(arg1);
  }

  bool DoExecute(Args &command, CommandReturnObject &result) override {
    auto c3 = GetDefaultThread()->c3_get();

    const size_t argc = command.GetArgumentCount();
    if (argc == 0 || argc > 2) {
      result.AppendErrorWithFormat("%s takes 1-2 argument.\n",
                                   m_cmd_name.c_str());
      return false;
    }

    const char *cmd_arg = command.GetArgumentAtIndex(0);

    if (strcmp(cmd_arg, "dump") == 0) {
      result.AppendMessageWithFormat("%-10s: %s\n", "data key",
                                     c3->get_data_key_str().c_str());
      result.AppendMessageWithFormat("%-10s: %s\n", "ptr key",
                                     c3->get_ptr_key_str().c_str());
      return true;
    }

    if (strcmp(cmd_arg, "data_key") == 0) {
      lldbassert(argc == 2);
      const size_t key_buf_size = C3Support::c3_data_key_size;
      uint8_t key_buf[key_buf_size];

      auto arg = command.GetArgumentAtIndex(1);
      lldbassert(key_buf_size * 2 == strlen(arg));

      string_to_hex_buf(key_buf, arg, key_buf_size * 2);
      c3->set_data_key(key_buf);

      result.AppendMessageWithFormat(
          "C3 data key set to: 0x%s\n",
          buf_to_hex_string(key_buf, key_buf_size).c_str());
      return true;
    }

    if (strcmp(cmd_arg, "ptr_key") == 0) {
      lldbassert(argc == 2);
      const size_t key_buf_size = C3Support::c3_ptr_key_size;
      uint8_t key_buf[key_buf_size];

      auto arg = command.GetArgumentAtIndex(1);
      lldbassert(key_buf_size * 2 == strlen(arg));

      string_to_hex_buf(key_buf, arg, key_buf_size * 2);
      c3->set_ptr_key(key_buf);

      result.AppendMessageWithFormat(
          "C3 pointer key set to: 0x%s\n",
          buf_to_hex_string(key_buf, key_buf_size).c_str());
      return true;
    }

    result.AppendErrorWithFormat("%s, unknown command: %s\n",
                                 m_cmd_name.c_str(), cmd_arg);
    return false;
  }
};

class CommandObjectC3CAs : public CommandObjectParsed {
public:
  CommandObjectC3CAs(CommandInterpreter &interpreter)
      : CommandObjectParsed(
            interpreter, "c3 pointer", "C3 pointer encoding / decoding",
            "c3 pointer [encode|decode|get_ca|get_la] ptr [size] [version]",
            eCommandRequiresTarget | eCommandProcessMustBePaused) {

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
    auto c3 = GetDefaultThread()->c3_get();

    const size_t argc = command.GetArgumentCount();
    if (argc == 0 || argc > 4) {
      result.AppendErrorWithFormat("%s takes 1-2 arguments.\n",
                                   m_cmd_name.c_str());
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
      uint64_t la = c3->decode_ptr(ca);

      result.AppendMessageWithFormat("decode_ptr: 0x%016lx -> 0x%016lx\n", ca,
                                     la);
      return true;
    }

    if (strcmp(cmd_arg, "encode") == 0) {
      if (argc < 3 || argc > 5) {
        result.AppendError("Bad number of args");
        return false;
      }
      const char *ptr_arg = command.GetArgumentAtIndex(1);

      uint64_t size = 0;
      uint64_t version = 0;

      char *endptr;
      size = strtoul(command.GetArgumentAtIndex(2), &endptr, 10);
      if (errno == ERANGE || *endptr != '\0') {
        result.AppendErrorWithFormat("Cannot convert to size (uint64_t): %s",
                                     command.GetArgumentAtIndex(3));
        return false;
      }

      if (argc == 4) {
        version = strtoul(command.GetArgumentAtIndex(2), &endptr, 10);
        if (errno == ERANGE || *endptr != '\0') {
          result.AppendErrorWithFormat("Cannot convert to size (uint64_t): %s",
                                       command.GetArgumentAtIndex(3));
          return false;
        }
      }

      Status error;
      lldb::addr_t addr = OptionArgParser::ToAddress(
          &m_exe_ctx, ptr_arg, LLDB_INVALID_ADDRESS, &error);
      if (addr == LLDB_INVALID_ADDRESS) {
        result.AppendErrorWithFormat("invalid address: %s", ptr_arg);
        result.AppendError(error.AsCString());
        return false;
      }

      if (is_encoded_cc_ptr(addr)) {
        result.AppendErrorWithFormat("Cannot encode CA (0x%016lx)\n", addr);
        return false;
      }

      const uint64_t la = (uint64_t)addr;
      const uint64_t ca = c3->encode_ptr(la, size, version);

      result.AppendMessageWithFormat("encode_ptr: 0x%016lx -> 0x%016lx\n", la,
                                     ca);
      return true;
    }

    if (strcmp(cmd_arg, "get_la") == 0) {
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
      if (!is_encoded_cc_ptr(ca)) {
        result.AppendMessageWithFormat("not a CA, returning as is: 0x%016lx\n",
                                       ca);
        return true;
      }

      uint64_t la = c3->decode_ptr(ca);
      result.AppendMessageWithFormat("decode_ptr: 0x%016lx -> 0x%016lx\n", ca,
                                     la);
      return true;
    }

    if (strcmp(cmd_arg, "get_ca") == 0) {
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

      uint64_t la = (uint64_t)addr;
      uint64_t ca = 0;

      if (is_encoded_cc_ptr(la)) {
        const uint64_t ca = la;
        result.AppendMessageWithFormat("decoding 0x%016lx -> 0x%016lx\n", ca,
                                       la);
        la = c3->decode_ptr(ca);
      }

      ca = c3->find_ca(la);
      if (ca != c3_lldb::C3Support::bad_ca) {
        result.AppendMessageWithFormat(
            "get_ca: CA for 0x%016lx is likely 0x%016lx\n", la, ca);
        return true;
      }

      result.AppendMessageWithFormat(
          "Cannot determine correct CA for 0x%016lx\n", la);
      return false;
    }

    result.AppendErrorWithFormat("%s, unknown command: %s\n",
                                 m_cmd_name.c_str(), cmd_arg);
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
