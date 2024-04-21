using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public abstract class BaseType { }

class IdentifierLiteral : BaseType
{
    public required string mName;
}

class NumberLiteral : BaseType
{
    public required ulong mValue;
}

class NestedName : BaseType
{
    public BaseType? mLeft;
    public required BaseType mRight;
}

class QualifiedId : BaseType
{
    public required BaseType mLeft;
    public required BaseType mRight;
}

class TemplatedType : BaseType
{
    public required BaseType mBase;
    public required BaseType mGenerics;
}

class Generic : BaseType
{
    public required List<BaseType> mTypes;
}

class SimpleTypeSpecifier : BaseType
{
    public BaseType? mLeft;
    public required BaseType mRight;
}

class Type : BaseType
{
    public required string mName;
}

class PointerOperation : BaseType
{
    public required BaseType mLeft;
    public required BaseType mRight;
}

class CVQualifier : BaseType
{
    public bool mIsConst = false;
    public bool mIsVolatile = false;
}

class CVQualifierSequence : BaseType
{
    public required List<CVQualifier> mQualifiers;
}

class PtrOperator : BaseType
{
    public BaseType? mLeft;
    public required string mOperator;
    public CVQualifierSequence? mQualifiers;
}