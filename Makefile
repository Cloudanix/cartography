<<<<<<< HEAD
test: test_lint test_unit

test_lint:
	flake8

test_unit:
	pytest tests/unit
=======
test: test_lint test_unit test_integration

test_lint:
	pre-commit run --all-files --show-diff-on-failure

test_unit:
	pytest -vvv --cov-report term-missing --cov=cartography tests/unit

test_integration:
	pytest -vvv --cov-report term-missing --cov=cartography tests/integration
>>>>>>> a3330bed20ae5391fff7799244d37733f61ce15a
