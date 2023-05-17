import atheris
import sys

from email_validator import validate_email, EmailNotValidError
import validators

def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    
    email = fdp.ConsumeString(20)

    valid2 = validators.email(email)

    try:
        valid = validate_email(email)

        if valid2 == False:
            print(email)
            print(valid)
            print(valid2)
            raise Exception("diff validate_email true / validators.email false")

    except EmailNotValidError:
        if valid2 == True:
            print(email)
            print(valid2)
            raise Exception("diff validate_email false / validators.email true")

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()