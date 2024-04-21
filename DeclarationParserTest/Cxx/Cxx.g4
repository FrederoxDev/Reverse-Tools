grammar Cxx;

/* Parser */
declSpecifier:
    typeSpecifier;

typeSpecifier:
    trailingTypeSpecifier;

trailingTypeSpecifier:
    simpleTypeSpecifier;

simpleTypeSpecifier
    : '::'? nestedNameSpecifier? typeName
    | primitiveType
    ;

primitiveType:
    | 'char'
    | 'char16_t' 
    | 'char32_t' 
    | 'wchar_t'
    | 'bool'
    | 'short'
    | 'int'
    | 'long'
    | 'signed'
    | 'unsigned'
    | 'float'
    | 'double'
    | 'void'
    | 'auto'
    ;

ptrOperator
    : '*' /*attributeSpecififerSeq?*/ cvQualifierSeq?
    | '&' /*attributeSpecififerSeq?*/
    | '&&' /*attributeSpecififerSeq?*/
    | '::'? nestedNameSpecifier '*' /*attributeSpecififerSeq?*/ cvQualifierSeq?
    ;

cvQualifierSeq
    : cvQualifier (cvQualifier)*
    ;

cvQualifier
    : 'const'
    | 'volatile'
    ;

ptrDeclarator
    : noptrDeclarator
    | ptrOperator ptrDeclarator
    ;

noptrDeclarator
    : declaratorId /*attributeSpecififerSeq?*/
    ;

declaratorId
    : '...'? idExpression
    | '::'? nestedNameSpecifier? className
    ;

className
    : identifier
    | simpleTemplateId
    ;

idExpression
    : unqualifiedId
    | qualifiedId ;

unqualifiedId
    : identifier 
    | simpleTemplateId;

qualifiedId
    : '::'? nestedNameSpecifier unqualifiedId;

simpleTemplateId:
    identifier '<' templateArgumentList? '>' ;

nestedNameSpecifier
    : typeName '::' 
    | nestedNameSpecifier identifier '::' ;

typeName
    : simpleTemplateId
    | identifier;

templateArgumentList
    : templateArgument (', ' templateArgument)*;

templateArgument
    : number
    | idExpression;

number:
    DIGIT+ ;

identifier
    : NON_DIGIT (DIGIT | NON_DIGIT)*;

/* Lexer */
NON_DIGIT : ([a-z] | [A-Z] | '_') ;
DIGIT : [0-9] ;
WS : [ \t\r\n]+ -> skip;