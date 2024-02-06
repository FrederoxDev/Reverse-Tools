from Lexer import Lexer
from Parser import Parser
from Analyser import parameter_types, function_name, class_name

#tokens = Lexer("BlockLegacy::liquidCanFlowIntoFromDirection(unsigned char,std::__1::function<Block const& ()(BlockPos const&)> const&,BlockPos const&)const").tokenise()
tokens = Lexer("void ItemRegistryRef<T>::j::registerItem()").tokenise()
# tokens = Lexer("void __fastcall BlockLegacy::~BlockLegacy(BlockLegacy *)").tokenise()

parser = Parser(tokens)
function = parser.parse()

print(function)

print(class_name(function))