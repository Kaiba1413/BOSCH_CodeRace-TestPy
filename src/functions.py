from flask import render_template_string
import atheris
import sys


def hello(username: str) -> str:
    template = f"<p>Hello {username}</p>" 
    return render_template_string(template) 

def product(operation: str):
    eval(f"product_{operation}()") 
    return "OK"

def redirect(url: str):
    return redirect(url) 

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    username = fdp.ConsumeString(20)
    try:
        hello(username)
    except:
        raise Exception("Hello "+ username + " failed!")

    operation = fdp.ConsumeString(20)
    try:
        product(operation)
    except:
        raise Exception("Product "+ operation + " failed!")
    
    url = fdp.ConsumeString(20)
    try:
        redirect(url)
    except:
        raise Exception("Hello "+ url + " failed!")

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()