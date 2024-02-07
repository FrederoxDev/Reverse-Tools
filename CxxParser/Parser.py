from typing import List

class Parser:
    tokens: []
    idx: int

    def __init__(self, tokens) -> None:
        self.tokens = tokens
        self.idx = 0

    def consume_token(self, type, value: str | None):
        token = self.tokens[self.idx]

        if token[0] != type:
            raise Exception(f"Expected token of type {type} instead got {token}")

        # Optional value check
        if value is None:
            self.idx += 1
            return token[1]

        if token[1] != value:
            raise Exception(f"Expected symbol {value} instead got {token}")
        
        self.idx += 1
        return value

    def try_consume_token(self, type, values: List[str] | None | str):
        if self.idx >= len(self.tokens):
            return None
        
        token = self.tokens[self.idx]

        # Make sure that this is an identifier
        if token[0] != type: 
            return None
        
        if values is None:
            self.idx += 1
            return token[1]
        
        if isinstance(values, str):
            if values == token[1]:
                self.idx += 1
                return token[1]
            
            return None
        
        for value in values:
            if value == token[1]:
                self.idx += 1
                return token[1]

    def parse_params(self, closing_char):
        closing_brace = self.try_consume_token("Symbol", closing_char)
        if closing_brace is not None:
            return
        
        params = [ self.parse_type() ]
        
        while self.try_consume_token("Symbol", ",") is not None:
            params.append(self.parse_type())

        self.consume_token("Symbol", closing_char)
        return params

    def parse_type(self):
        is_const = self.try_consume_token("Keyword", "const") is not None 
        is_unsigned = self.try_consume_token("Keyword", "unsigned") is not None
        
        #TODO: Store this :!
        self.try_consume_token("Keyword", ["struct", "enum", "class"])

        name = self.try_consume_token("Identifier", None)
        generics = []
        namespace = None

        generic_open = self.try_consume_token("Symbol", "<")
        if generic_open is not None:
            generics = self.parse_params(">")

        namespace_open = self.try_consume_token("Symbol", ":")
        if namespace_open is not None:
            self.consume_token("Symbol", ":")
            namespace = self.parse_type()

            # Propagate right aligned const upwards!
            if namespace["is_const"]:
                namespace["is_const"] = False
                is_const = True

            return {
                "namespace": name,
                "generics": generics,
                "type": {
                    "name": namespace,
                },
                "is_const": is_const,
                "is_unsigned": is_unsigned
            }
        
        # For right aligned const
        is_const = self.try_consume_token("Keyword", "const") is not None or is_const
    
        ptrs_and_const = []
        
        while True:
            const_keyword = self.try_consume_token("Keyword", "const")
            if const_keyword is not None:
                ptrs_and_const.append("const")
                continue
            
            ptr_keyword = self.try_consume_token("Symbol", "*")
            if ptr_keyword is not None:
                ptrs_and_const.append("*")
                continue
            
            break
            
        ref_count = 0
        
        # Passing rvalues (&&)
        while self.try_consume_token("Symbol", "&") is not None:
            ref_count += 1

        params = []
        # Things like std::function<int(int, int)>!
        if self.try_consume_token("Symbol", "(") is not None:
            params = self.parse_params(")")

        call_signature = []
        if self.try_consume_token("Symbol", "(") is not None:
            call_signature = self.parse_params(")")

        # Swap around call signature and parameters if the call signature is found!
        if len(call_signature) != 0:
            temp = params
            params = call_signature
            call_signature = temp

        return {
            "name": name,
            "generics": generics,
            "is_const": is_const,
            "is_unsigned": is_unsigned,
            "ref_count": ref_count,
            "ptrs_and_const": ptrs_and_const,
            "params": params,
            "call_signature": call_signature
        }

    def parse(self):
        publicity = self.try_consume_token("Identifier", [ "private", "public", "protected" ])
        if publicity is not None:
            self.consume_token("Symbol", ":")

        modifiers = self.try_consume_token("Identifier", [ "virtual", "static" ])

        return_type = self.parse_type() 

        # This function has no return type and what we have just parsed was actually the function itself
        if len(self.tokens) - 1 <= self.idx:
            return {
                "body": return_type,
                "return_type": None
            }

        calling_convention = self.try_consume_token("Identifier", ["__thiscall", "__fastcall"])
        body = self.parse_type()

        return {
            "body": body,
            "return_type": return_type,
            "publicity": publicity,
            "modifier": modifiers,
            "calling_convention": calling_convention
        }