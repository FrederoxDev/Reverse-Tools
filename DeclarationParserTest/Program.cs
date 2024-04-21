using Antlr4.Runtime;

namespace AmethystHeaders
{
    internal class Program
    {
        static Demangler gDemangler;

        static void Main(string[] args)
        {
            string input = "::hello<wow::amazing>* const volatile";
            AntlrInputStream inputStream = new(input);
            CxxLexer cxxLexer = new(inputStream);
            CommonTokenStream commonTokenStream = new(cxxLexer);
            CxxParser cxxParser = new(commonTokenStream);

            var context = cxxParser.ptrDeclarator();
            CxxVisitor visitor = new CxxVisitor();
            BaseType result = visitor.Visit(context);

            Console.WriteLine(context.ToStringTree());

            Console.ReadLine();
        }
    }
}
