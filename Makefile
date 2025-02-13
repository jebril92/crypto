PYTHON_FILES = algebra.py dsa.py ecdsa.py ecelgamal.py elgamal.py rfc7748.py

PYTHON = python3

.PHONY: test-dsa test-ecdsa test-elgamal test-ecelgamal lint clean

test-dsa:
        $(PYTHON) dsa.py

test-ecdsa:
        $(PYTHON) ecdsa.py

test-elgamal:
        $(PYTHON) elgamal.py

test-ecelgamal:
        $(PYTHON) ecelgamal.py

clean:
        rm -rf __pycache__
        rm -f *.pyc *~
