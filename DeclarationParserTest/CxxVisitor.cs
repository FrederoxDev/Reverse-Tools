using Antlr4.Runtime.Misc;

public class CxxVisitor : CxxBaseVisitor<BaseType>
{
    public override BaseType VisitPtrOperator([NotNull] CxxParser.PtrOperatorContext context)
    {
        CVQualifierSequence? qualifiers = null;
        if (context.cvQualifierSeq() != null)
        {
            qualifiers = VisitCvQualifierSeq(context.cvQualifierSeq()) as CVQualifierSequence;
        }

        if (context.nestedNameSpecifier() != null)
        {
            BaseType left = Visit(context.nestedNameSpecifier());
            return new PtrOperator()
            {
                mOperator = "*",
                mLeft = left,
                mQualifiers = qualifiers
            };
        }

        return new PtrOperator()
        {
            mOperator = context.GetChild(0).GetText(),
            mQualifiers = qualifiers
        };
    }

    public override BaseType VisitCvQualifier([NotNull] CxxParser.CvQualifierContext context)
    {
        return new CVQualifier()
        {
            mIsConst = context.GetText() == "const",
            mIsVolatile = context.GetText() == "volatile"
        };
    }

    public override BaseType VisitCvQualifierSeq([NotNull] CxxParser.CvQualifierSeqContext context)
    {
        List<CVQualifier> qualifiers = new();

        foreach (var child in context.children)
        {
            if (child is CxxParser.CvQualifierContext typeContext)
            {
                CVQualifier qualifier = (VisitCvQualifier(typeContext) as CVQualifier)!;
                qualifiers.Add(qualifier);
            }
        }

        return new CVQualifierSequence()
        {
            mQualifiers = qualifiers
        };
    }

    public override BaseType VisitPtrDeclarator([NotNull] CxxParser.PtrDeclaratorContext context)
    {
        if (context.noptrDeclarator() != null)
        {
            throw new Exception("noptrDeclarator not handled yet");
        }

        BaseType ptrOperator = Visit(context.ptrOperator());
        BaseType ptrDeclarator = Visit(context.ptrDeclarator());

        return new PointerOperation()
        {
            mLeft = ptrOperator,
            mRight = ptrDeclarator
        };
    }

    public override BaseType VisitSimpleTypeSpecifier([NotNull] CxxParser.SimpleTypeSpecifierContext context)
    {
        if (context.typeName() != null)
        {
            return new SimpleTypeSpecifier()
            {
                mLeft = Visit(context.nestedNameSpecifier()),
                mRight = Visit(context.typeName())
            };
        }

        if (context.primitiveType() != null)
        {
            return new Type()
            {
                mName = context.primitiveType().GetText()
            };
        }

        throw new Exception("jo");
    }

    public override BaseType VisitIdExpression([NotNull] CxxParser.IdExpressionContext context)
    {
        return base.VisitIdExpression(context);
    }

    public override BaseType VisitUnqualifiedId([NotNull] CxxParser.UnqualifiedIdContext context)
    {
        if (context.identifier() != null)
        {
            return Visit(context.identifier());
        } 

        if (context.simpleTemplateId() != null)
        {
            return Visit(context.simpleTemplateId());
        }

        throw new Exception("Unhandled UnqualifiedId case");
    }

    public override BaseType VisitSimpleTemplateId([NotNull] CxxParser.SimpleTemplateIdContext context)
    {
        return new TemplatedType()
        {
            mBase = Visit(context.identifier()),
            mGenerics = Visit(context.templateArgumentList())
        };
    }

    public override BaseType VisitTemplateArgumentList([NotNull] CxxParser.TemplateArgumentListContext context)
    {
        List<BaseType> types = new();

        foreach (var child in context.children)
        {
            if (child is CxxParser.TemplateArgumentContext typeContext)
            {
                types.Add(Visit(typeContext));
            }
        }

        return new Generic()
        {
            mTypes = types
        };
    }

    public override BaseType VisitQualifiedId([NotNull] CxxParser.QualifiedIdContext context)
    {
        var child = context.GetChild(0);
        if (child != null && child.GetText() == "::") 
        {
            /* Using :: to indicate its in the global namespace, handle later if needed */
            throw new Exception("Visit QualifiedId does not yet support leading ::");
        }

        if (context.nestedNameSpecifier() != null && context.unqualifiedId() != null)
        {
            return new QualifiedId()
            {
                mLeft = Visit(context.nestedNameSpecifier()),
                mRight = Visit(context.unqualifiedId())
            };
        }

        throw new Exception("VisitQualifiedId Unhandled case");
    }

    public override BaseType VisitTypeName([NotNull] CxxParser.TypeNameContext context)
    {
        if (context.simpleTemplateId() != null)
        {
            return Visit(context.simpleTemplateId()); 
        }

        if (context.identifier() != null)
        {
            return Visit(context.identifier());
        }

        throw new Exception("od");
    }

    public override BaseType VisitIdentifier([NotNull] CxxParser.IdentifierContext context)
    {
        return new IdentifierLiteral()
        {
            mName = context.GetText()
        };
    }

    public override BaseType VisitNumber([NotNull] CxxParser.NumberContext context)
    {
        return new NumberLiteral()
        {
            mValue = ulong.Parse(context.GetText())
        };
    }

    public override BaseType VisitTemplateArgument([NotNull] CxxParser.TemplateArgumentContext context)
    {
        if (context.number() != null)
        {
            return Visit(context.number());
        }

        else if (context.idExpression() != null)
        {
            return Visit(context.idExpression());
        }

        throw new Exception("Visit template argument unhandled");
    }

    public override BaseType VisitNestedNameSpecifier([NotNull] CxxParser.NestedNameSpecifierContext context)
    {
        if (context.typeName() != null)
        {
            return new NestedName()
            {
                mRight = Visit(context.typeName())
            };
        }

        if (context.nestedNameSpecifier() != null)
        {
            return new NestedName()
            {
                mLeft = Visit(context.nestedNameSpecifier()),
                mRight = Visit(context.identifier())
            };
        }

        throw new Exception("Unhandled nested name specifier path");
    }
}
