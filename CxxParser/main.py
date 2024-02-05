from Lexer import Lexer
from Parser import Parser

tokens = Lexer("std::__1::function<Block const& ()(BlockPos const&)> const&").tokenise()
print("tokens", tokens)

Parser(tokens).parse()