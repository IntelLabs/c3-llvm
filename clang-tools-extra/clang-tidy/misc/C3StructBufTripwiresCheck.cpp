//===--- C3StructBufTripwiresCheck.cpp - clang-tidy -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "C3StructBufTripwiresCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Lex/Lexer.h"

using namespace clang::ast_matchers;

namespace clang::tidy::misc {

void C3StructBufTripwiresCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(recordDecl().bind("x"), this);
}

void C3StructBufTripwiresCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *MatchedDecl = Result.Nodes.getNodeAs<RecordDecl>("x");

  clang::FieldDecl *prev = NULL;
  clang::FieldDecl *prev_field = NULL;
  for (clang::FieldDecl *field: MatchedDecl->fields()) {
	  if (field == NULL)
		  continue;
	  clang::QualType qualtype = field->getType();
	  if (isa<clang::ConstantArrayType>(qualtype.getTypePtr())) {
	      if (prev_field && prev_field != prev) {
		  const auto FieldRange = clang::CharSourceRange::getCharRange(
		      field->getBeginLoc(),
		      field->getEndLoc().getLocWithOffset(+2));
		  diag(field->getLocation(), "[C3] field %0 is an array type non-adjacent to other array field")
		      << field << (clang::FieldDecl *)prev_field;
		  diag(prev_field->getEndLoc().getLocWithOffset(2), "move field %0 adjacent to field %1", DiagnosticIDs::Note)
		      <<field << prev_field << FixItHint::CreateInsertionFromRange(Lexer::getLocForEndOfToken(prev_field->getEndLoc().getLocWithOffset(2), 0, *Result.SourceManager, getLangOpts()), FieldRange)
		      << FixItHint::CreateRemoval(FieldRange);
	      }
              prev = field;
	      prev_field = field;
	  } else {
              prev = NULL;
	  }
  }
}

} // namespace clang::tidy::misc
