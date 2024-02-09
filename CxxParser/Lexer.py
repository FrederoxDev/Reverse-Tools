from typing import TypedDict, List, TypeVar, Optional
import re

whitespace_rule = r'\s'
identifier_rule = r'[a-zA-Z_~]\w*$'
in_identifier_rule = r'[a-zA-Z_~0-9]\w*$'
symbol_rule = r'[.,<>():*&]'
keywords = ["virtual", "static", "const", "class", "struct", "enum", "unsigned", "public", "private", "protected",
            "__thiscall", "__fastcall"
            ]

class Lexer:
    idx: int
    text: str
    tokens: []

    def __init__(self, text: str) -> None:
        self.idx = 0
        self.tokens = []
        self.text = text

    # Checks the current symbol to see if it matches a rule
    def match(self, rule) -> bool:
        if self.idx >= len(self.text):
            return False
        
        return re.match(rule, self.text[self.idx]) is not None

    def identifier(self):
        identifier = ""

        while self.match(in_identifier_rule):
            identifier += self.text[self.idx]
            self.idx += 1

        if identifier in keywords:
            self.tokens.append(("Keyword", identifier))
            
        else:
            self.tokens.append(("Identifier", identifier))

    def symbol(self):
        char = self.text[self.idx]
        self.idx += 1
        self.tokens.append(("Symbol", char))

    def tokenise(self):
        while self.idx < len(self.text):
            # Ignore Whitespace
            if self.match(whitespace_rule):
                self.idx += 1
                continue

            # Identifiers (keywords, class names, etc..)
            elif self.match(identifier_rule): self.identifier()

            # Symbols (<, >, :, etc)
            elif self.match(symbol_rule): self.symbol()

            # No rule to match
            else: 
                print(f"Lexer Skipping '{self.text[self.idx]}'")
                self.idx += 1

        return self.tokens