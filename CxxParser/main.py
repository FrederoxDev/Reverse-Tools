from Lexer import Lexer
from Parser import Parser
from Analyser import parameter_types, function_name, class_name, type_to_str, get_all_types_used

tokens = Lexer("public: virtual bool BlockLegacy::mayPlace(class BlockSource &,class BlockPos&)const").tokenise()

parser = Parser(tokens)

function = parser.parse()

classes = set()
enums = set()
structs = set()