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

    def parse_type(self):
        # is_const = self.try_consume_token("Identifier", "const") is not None 
        # is_unsigned = self.try_consume_token("Identifier", "unsigned") is not None

        # print("is_const", is_const, "is_unsigned", is_unsigned)

        name = self.consume_token("Identifier", None)
        generic = None
        namespace = None

        generic_open = self.try_consume_token("Symbol", "<")
        if generic_open is not None:
            print(self.idx)
            generic = self.parse_type()
            self.consume_token("Symbol", ">")

        namespace_open = self.try_consume_token("Symbol", ":")
        if namespace_open is not None:
            self.consume_token("Symbol", ":")
            namespace = self.parse_type()

            return {
                "namespace": name,
                "generic": generic,
                "type": {
                    "name": namespace,
                }
            }

        return {
            "name": name,
            "generic": generic
        }

    def parsed_type_to_str(self, parsed):
        if isinstance(parsed, str):
            return parsed
        
        stringified = ""

        if "namespace" in parsed:
            stringified += parsed["namespace"] 

            if "generic" in parsed:
                if parsed["generic"] is not None:
                    stringified += f"<{self.parsed_type_to_str(parsed['generic'])}>"

            stringified += f"::{self.parsed_type_to_str(parsed['type'])}"

            return stringified

        if "name" in parsed:
            if parsed["name"] is not None:
                stringified += self.parsed_type_to_str(parsed['name'])

        if "generic" in parsed:
            if parsed["generic"] is not None:
                stringified += f"<{self.parsed_type_to_str(parsed['generic'])}>"

        return stringified

    def parse(self):
        # publicity = self.try_consume_token("Identifier", [ "private", "public", "protected" ])

        # if publicity is not None:
        #     self.consume_token("Symbol", ":")

        # modifiers = self.try_consume_token("Identifier", [ "virtual", "static" ])

        return_type = self.parse_type()    
        print(return_type)
        print("type: ", self.parsed_type_to_str(return_type))