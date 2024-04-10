# Usage Guide

1. Run `dump_linux_vtable.py` on your target versions linux server, this will dump every vtable on the linux build into a json file at `%AMETHYST%/tools/linux_vtable.json`.

2. Next run `SymbolDumper.exe <pdb>`, and pass in the path to your target versions windows servers `.pdb`. This will dump all symbols from the server as IDA can only read one symbol for an address.