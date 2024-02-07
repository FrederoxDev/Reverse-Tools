from Lexer import Lexer
from Parser import Parser
from Analyser import parameter_types, function_name, class_name, type_to_str

# class std::shared_ptr<struct BlockLegacy::AlteredStateCollection> * std::_Uninitialized_move<class std::shared_ptr<struct BlockLegacy::AlteredStateCollection> *,class std::allocator<class std::shared_ptr<struct BlockLegacy::AlteredStateCollection>>>(class std::shared_ptr<struct BlockLegacy::AlteredStateCollection> * const,class std::shared_ptr<struct BlockLegacy::AlteredStateCollection> * const,class std::shared_ptr<struct BlockLegacy::AlteredStateCollection> *,class std::allocator<class std::shared_ptr<struct BlockLegacy::AlteredStateCollection>> &)
tokens = Lexer("public: virtual bool mayPlace(class BlockSource &,class BlockPos const &)const").tokenise()

parser = Parser(tokens)

function = parser.parse()

print(function)

print(f"func_name: '{function_name(function)}'")