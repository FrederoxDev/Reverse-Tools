from Lexer import Lexer
from Parser import Parser

# tokens = Lexer("protected: virtual int BlockLegacy::getBurnOdds(void)const").tokenise()
tokens = Lexer("hello::hi<j>").tokenise()
print("tokens", tokens)

Parser(tokens).parse()