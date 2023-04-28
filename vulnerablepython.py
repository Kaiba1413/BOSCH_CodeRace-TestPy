import atheris

with atheris.instrument_imports():
  import some_library
  import sys

def TestOneInput(data):
  some_library.parse(data)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()