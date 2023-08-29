//===-- CommandObjectC3.h -------------------------------------*- C++ -*-===//
//
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_COMMANDS_COMMANDOBJECTC3_H
#define LLDB_SOURCE_COMMANDS_COMMANDOBJECTC3_H

#include "lldb/Interpreter/CommandObject.h"
#include "lldb/Interpreter/CommandObjectMultiword.h"

namespace lldb_private {

// CommandObjectC3

class CommandObjectC3 : public CommandObjectMultiword {
public:
  CommandObjectC3(CommandInterpreter &interpreter);

  ~CommandObjectC3() override;

  // protected:
  // bool DoExecute(Args &args, CommandReturnObject &result) override;

  // bool ShouldAskForConfirmation(bool &is_a_detach);
};

} // namespace lldb_private

#endif // LLDB_SOURCE_COMMANDS_COMMANDOBJECTC3_H
