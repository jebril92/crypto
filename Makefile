PYTHON_FILES = algebra.py dsa.py ecdsa.py ecelgamal.py elgamal.py rfc7748.py

PYTHON = python3
TEST_DIR = tests

.PHONY: test clean server client

server:
	$(PYTHON) server.py

client:
	$(PYTHON) client.py

test:
	$(PYTHON) run_tests.py

clean:
	rm -rf __pycache__ $(TEST_DIR)/__pycache__
	rm -f *.pyc *~
