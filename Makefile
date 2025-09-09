format:
	poetry run ruff format getsploit

isort:
	poetry run ruff check --select I --fix getsploit

mypy:
	poetry run mypy getsploit

mypy-one:
	poetry run mypy ${ARGS}

cc:
	make format
	make isort
