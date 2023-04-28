import atheris
import sys

def TestOneInput(data):
  if data == b"bad":
    raise RuntimeError("Badass")

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()