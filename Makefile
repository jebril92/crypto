PYTHON_FILES = algebra.py dsa.py ecdsa.py ecelgamal.py elgamal.py rfc7748.py

PYTHON = python3
TEST_DIR = tests

.PHONY: test test-dsa test-ecdsa test-elgamal test-ecelgamal lint clean

test:
	$(PYTHON) -m pytest $(TEST_DIR)

test-dsa:
	$(PYTHON) -m pytest $(TEST_DIR)/test_dsa.py

test-ecdsa:
	$(PYTHON) -m pytest $(TEST_DIR)/test_ecdsa.py

test-elgamal:
	$(PYTHON) -m pytest $(TEST_DIR)/test_elgamal.py

test-ecelgamal:
	$(PYTHON) -m pytest $(TEST_DIR)/test_ecelgamal.py

clean:
	rm -rf __pycache__ $(TEST_DIR)/__pycache__
	rm -f *.pyc *~
