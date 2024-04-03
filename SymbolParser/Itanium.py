import json
from typing import List

class Itanium:
    pos: int
    symbol: str

    def __init__(self, symbol: str) -> None:
        self.symbol = symbol
        self.pos = 0
        
    def error(self, reason: str) -> None:
        self.log_remaining()
        raise Exception(reason)
    
    def log_remaining(self):
        print("Remaining:" + self.symbol[self.pos:])
        
    def try_consume(self, values: str | List[str]) -> str | None:
        current = self.symbol[self.pos:]
        
        if isinstance(values, str):
            if not current.startswith(values):
                return None
            
            if self.pos + len(values) >= len(self.symbol):
                return None
            
            self.pos += len(values)
            return values
        
        for value in values:
            res = self.try_consume(value)
            if res:
                return res
            
        return None
    
    # <CV-qualifiers>      ::= [r] [V] [K] 	  # restrict (C99), volatile, const
    def parse_cv_qualifiers(self):
        restricted = self.try_consume("r")
        volatile = self.try_consume("V")
        const = self.try_consume("K")
        
        return {
            "restricted": restricted != None,
            "volatile": volatile != None,
            "const": const != None
        }
        
    # <ref-qualifier>      ::= R              # & ref-qualifier
    # <ref-qualifier>      ::= O              # && ref-qualifier
    def parse_ref_qualifier(self):
        ref = self.try_consume("R")
        if ref:
            return "&"
        
        rvalue = self.try_consume("O")
        if rvalue:
            return "&&"
        
        return None
    
    # _A-Za-z0-9.
    def parse_identifier(self, length: int):
        identifier = self.symbol[self.pos:self.pos + length]
        self.pos += length
        return identifier
    
    # <ctor-dtor-name> ::= C1			            # complete object constructor
	# 	               ::= C2			            # base object constructor
	# 	               ::= C3			            # complete object allocating constructor
	# 	               ::= CI1 <base class type>	# complete object inheriting constructor
	# 	               ::= CI2 <base class type>	# base object inheriting constructor
	# 	               ::= D0			            # deleting destructor
	# 	               ::= D1			            # complete object destructor
	# 	               ::= D2			            # base object destructor
    def parse_ctor_dtor_name(self):        
        complete_object_ctor = self.try_consume("C2")
        if complete_object_ctor:
            return "base_object_constructor"
        
        not_implemented = self.try_consume(["C1", "C3", "CI1", "CI2", "D0", "D1", "D2"])
        if not_implemented:
            self.error(f"{not_implemented} has not been implemented!")
            
        return None
    
    # <source-name> ::= <positive length number> <identifier>
    def parse_source_name(self):
        number_str = ""
        
        if self.pos >= len(self.symbol):
            return None
        
        first = self.symbol[self.pos]
        if not first.isdigit():
            return None
        
        while self.symbol[self.pos].isdigit():
            number_str += self.symbol[self.pos]
            self.pos += 1
            
        return self.parse_identifier(int(number_str))
    
    # <unqualified-name> ::= <operator-name> [<abi-tags>]
    #                    ::= <ctor-dtor-name>  
    #                    ::= <source-name>   
    #                    ::= <unnamed-type-name>   
    #                    ::= DC <source-name>+ E      # structured binding declaration
    def parse_unqualified_name(self):
        ctor_dtor_name = self.parse_ctor_dtor_name()
        if ctor_dtor_name: return ctor_dtor_name
    
        source_name = self.parse_source_name()
        if source_name: return source_name
    
        return None
    
    # <prefix> ::= <unqualified-name>                 # global class or namespace
    #          ::= <prefix> <unqualified-name>        # nested class or namespace
	#          ::= <template-prefix> <template-args>  # class template specialization
    #          ::= <closure-prefix>                   # initializer of a variable or data member
    #          ::= <template-param>                   # template type parameter
    #          ::= <decltype>                         # decltype qualifier
	#          ::= <substitution>
    def parse_prefix(self):
        return self.parse_unqualified_name()
    
    # <nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
    # 		        ::= N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <template-args> E
    def parse_nested_name(self):
        cv_qualifiers = self.parse_cv_qualifiers()
        ref_qualifier = self.parse_ref_qualifier()
        
        prefix = self.parse_prefix()
        if prefix:
            nested_name = self.parse_unqualified_name()
            
            e = self.try_consume("E")
            if not e:
                self.error("Expected E at the end of <nested-name>")
                
            return {
                "cv_qualifiers": cv_qualifiers,
                "ref_qualifier": ref_qualifier,
                "prefix": prefix,
                "nested_name": nested_name
            }
            
        else:
            self.error("<template-prefix> not implemented")

        return None
      
    # <unscoped-name> ::= <unqualified-name>
	# 	            ::= St <unqualified-name>   # ::std::  
    def parse_unscoped_name(self):
        unqualified_name = self.parse_unqualified_name()
        if unqualified_name: return unqualified_name
        
        st = self.try_consume("St")
        if st:
            self.error("<unscoped-name> St not implemented")
        
        return None
        
    # <name> ::= <nested-name>
    # 	     ::= <unscoped-name>
    # 	     ::= <unscoped-template-name> <template-args>
    # 	     ::= <local-name>
    def parse_name(self):
        nested_name = self.try_consume("N")
        if nested_name: return self.parse_nested_name()
        
        unscoped_name = self.parse_unscoped_name()
        if unscoped_name: return unscoped_name
        
        return None
    
    # <builtin-type> :: see on docs
    def parse_builtin_type(self):        
        builtins = [
            ("v", "void"),
            ("w", "wchar_t"),
            ("b", "bool"),
            ("c", "char"),
            ("a", "signed char"),
            ("h", "unsigned char"),
            ("s", "short"),
            ("t", "unsigned short"),
            ("i", "int"),
            ("j", "unsigned int"),
            ("l", "long"),
            ("m", "unsigned long"),
            ("x", "long long"),
            ("y", "unsigned long long"),
            ("n", "__int128"),
            ("o", "unsigned __int128"),
            ("f", "float"),
            ("d", "double"),
            ("e", "long double"),
            ("g", "__float128")
        ]
        
        for builtin in builtins:
            c = self.try_consume(builtin[0])
            if c:
                return {
                    "type": builtin[1]
                }
        
        unsupported = self.try_consume(["z", "u"])
        if unsupported:
            self.error(f"<builtin-type> does not support {unsupported}")
    
        return None
    
    # <extended-qualifier> ::= U <source-name> [<template-args>] # vendor extended type qualifier
    def parse_extended_qualifier(self):
        marker = self.try_consume("U")
        if marker:
            self.error("<extended-qualifier> not implemented")
            
        return None
    
    # <qualifiers>         ::= <extended-qualifier>* <CV-qualifiers>
    def parse_qualifiers(self):
        extended_qualifiers = []
        
        while True:
            q = self.parse_extended_qualifier()
            if not q:
                break
            
            extended_qualifiers.append(q)
            
        cv_qualifiers = self.parse_cv_qualifiers()
        if not cv_qualifiers["restricted"] and not cv_qualifiers["volatile"] and not cv_qualifiers["const"] and extended_qualifiers == []:
            return None
        
        return {
            "type": "qualifiers",
            "extended_qualifiers": extended_qualifiers,
            "cv_qualifiers": cv_qualifiers
        }
    
    # <qualified-type>     ::= <qualifiers> <type>
    def parse_qualified_type(self):
        qualifiers = self.parse_qualifiers()
        if not qualifiers:
            return None
        
        type = self.parse_type()
        if not type:
            self.error("Expected type")
        
        return {
            "type": "qualified_type",
            "qualifiers": qualifiers,
            "to": type
        }
        
    #  <class-enum-type> ::= <name>     # non-dependent type name, dependent type name, or dependent typename-specifier
    #                    ::= Ts <name>  # dependent elaborated type specifier using 'struct' or 'class'
    #                    ::= Tu <name>  # dependent elaborated type specifier using 'union'
    #                    ::= Te <name>  # dependent elaborated type specifier using 'enum'
    def parse_class_enum_type(self):
        name = self.parse_name()
        
        if name:
            return {
                "type": "class_enum_type",
                "specifier": "non_dependant",
                "name": name
            }
        
        ts = self.try_consume("Ts")
        if ts:
            name = self.parse_name()
            
            return {
                "type": "class_enum_type",
                "specifier": "struct_or_class",
                "name": name
            }
            
        ts = self.try_consume("Tu")
        if ts:
            name = self.parse_name()
            
            return {
                "type": "class_enum_type",
                "specifier": "union",
                "name": name
            }
            
        ts = self.try_consume("Ts")
        if ts:
            name = self.parse_name()
            
            return {
                "type": "class_enum_type",
                "specifier": "enum",
                "name": name
            }
    
        return None
    
    # <type> ::= <builtin-type>
    #      ::= <qualified-type>
    #      ::= <function-type>
    #      ::= <class-enum-type>
    #      ::= <array-type>
    #      ::= <pointer-to-member-type>
    #      ::= <template-param>
    #      ::= <template-template-param> <template-args>
    #      ::= <decltype>
    #      ::= P <type>        # pointer
    #      ::= R <type>        # l-value reference
    #      ::= O <type>        # r-value reference (C++11)
    #      ::= C <type>        # complex pair (C99)
    #      ::= G <type>        # imaginary (C99)
    #      ::= <substitution>  # See Compression below
    def parse_type(self):      
        builtin = self.parse_builtin_type()   
        if builtin: return builtin
             
        qualified_type = self.parse_qualified_type()
        if qualified_type: return qualified_type
        
        class_enum = self.parse_class_enum_type()
        if class_enum: return class_enum
        
        print("hi")
        
        if self.try_consume("R"):
            return {
                "type": "lvalue",
                "to": self.parse_type()
            }
            
        return None
    
    # <bare-function-type> ::= <signature type>+
    def parse_bare_function_type(self):
        types = []
        
        print("About to call parse_type")
        self.log_remaining()
        
        first = self.parse_type()
        print("first")
        print(first)
        
        if not first:
            return None
        
        types.append(first)
        
        while True:
            print("parsing type for bare")
            type = self.parse_type()
            if not type:
                break
            
            types.append(type)
            
        return types

    # <encoding> ::= <function name> <bare-function-type>
    # 	         ::= <data name>
    # 	         ::= <special-name>
    def parse_encoding(self):
        special_name = self.try_consume("T")
        if special_name:
            self.error("<special-name> not supported yet.")
        
        name = self.parse_name()
        bare_function_type = self.parse_bare_function_type()
        
        if not bare_function_type:
            return {
                "encoding": {
                    "type": "data_name",
                    "name": name
                }
            }
            
        return {
            "encoding": {
                "type": "function_name",
                "name": name,
                "bare_function_type": bare_function_type
            }
        }

    # <mangled-name> ::= _Z <encoding>
    #                ::= _Z <encoding> . <vendor-specific suffix>
    def parse_mangled_name(self):
        itanium_identifier = self.try_consume("_Z")
        if itanium_identifier == None:
            self.error("Itanium symbols must begin with _Z")
        
        encoding = self.parse_encoding()
        self.log_remaining()
        
        return encoding
        
# result = Itanium("_ZN11BlockLegacyC2ERKNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEEiRK8Material").parse_mangled_name()
itanium = None

try:
    itanium = Itanium("_ZN11JsonHelpers16getFieldAsObjectERKN4Json5ValueERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEE")
    result = itanium.parse_mangled_name()
    print(json.dumps(result))
    
except RecursionError as e:
    print("Infinite recursion")
    itanium.log_remaining()
    
    # raise e