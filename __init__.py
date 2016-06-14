# import AtumsoftUtils
# import AtumsoftDecorator
# import AtumsoftGeneric
# import AtumsoftLinux
# import AtumsoftWindows

# import all modules in package
import importlib
import os

for file in os.path.walk(os.path.normpath(__file__)):
    importlib.import_module(file, __name__)