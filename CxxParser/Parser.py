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

    def try_consume_token(self, type, values: List[str] | None):
        if self.idx >= len(self.tokens):
            return None
        
        token = self.tokens[self.idx]

        # Make sure that this is an identifier
        if token[0] != type: 
            return None
        
        if values is None:
            self.idx += 1
            return token[1]
        
        if token[1] in values:
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
        is_const = self.try_consume_token("Identifier", "const") is not None 
        is_unsigned = self.try_consume_token("Identifier", "unsigned") is not None

        name = self.consume_token("Identifier", None)
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
        
        # For west const
        is_const = self.try_consume_token("Identifier", "const") is not None or is_const
        is_ref = self.try_consume_token("Symbol", "&") is not None
        is_ptr = self.try_consume_token("Symbol", "*") is not None

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
            "is_ref": is_ref,
            "is_ptr": is_ptr,
            "params": params,
            "call_signature": call_signature
        }

    def parsed_type_to_str(self, parsed):
        if isinstance(parsed, str):
            return parsed
        
        stringified = ""

        if "is_const" in parsed:
            if parsed["is_const"]:
                stringified += "const "

        if "is_unsigned" in parsed:
            if parsed["is_unsigned"]:
                stringified += "unsigned "

        if "namespace" in parsed:
            stringified += parsed["namespace"] 

            if "generics" in parsed:
                if len(parsed["generics"]) != 0:
                    generics = list(map(self.parsed_type_to_str, parsed["generics"]))
                    stringified += f"<{', '.join(generics)}>"

            stringified += f"::{self.parsed_type_to_str(parsed['type'])}"

            return stringified

        if "name" in parsed:
            if parsed["name"] is not None:
                stringified += self.parsed_type_to_str(parsed['name'])

        if "generics" in parsed:
            if len(parsed["generics"]) != 0:
                generics = list(map(self.parsed_type_to_str, parsed["generics"]))
                stringified += f"<{', '.join(generics)}>"

        if "is_ptr" in parsed:
            if parsed["is_ptr"]:
                stringified += "*"

        if "is_ref" in parsed:
            if parsed["is_ref"]:
                stringified += "&"

        if "call_signature" in parsed:
            if parsed["call_signature"] is None:
                stringified += "()"

            elif len(parsed["call_signature"]) != 0:
                params = list(map(self.parsed_type_to_str, parsed["call_signature"]))
                stringified += f"({', '.join(params)})"

        if "params" in parsed:
            if parsed["params"] is None:
                stringified += "()"

            elif len(parsed["params"]) != 0:
                params = list(map(self.parsed_type_to_str, parsed["params"]))
                stringified += f"({', '.join(params)})"

        return stringified

    def parse(self):
        publicity = self.try_consume_token("Identifier", [ "private", "public", "protected" ])
        if publicity is not None:
            self.consume_token("Symbol", ":")

        modifiers = self.try_consume_token("Identifier", [ "virtual", "static" ])

        return_type = self.parse_type()    
        print(return_type)
        print("return type: ", self.parsed_type_to_str(return_type))