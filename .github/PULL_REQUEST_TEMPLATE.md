<!-- Keep this short. The gate below is what actually blocks a merge. -->

## What this changes

<!-- One or two sentences. Link the issue it closes, if there is one. -->

## Why

<!-- The behaviour that was wrong, or the capability that was missing. -->

## How it was verified

<!-- Commands and their outcome, not adjectives. `make check` covers the automated part;
     say what you also exercised by hand, especially for terminal layout or the database. -->

```console
$ make check
```

## Checklist

- [ ] `make check` passes locally (format, lint, types, secrets, 100% coverage, build)
- [ ] New behaviour is covered by a test that fails without the change
- [ ] `CHANGELOG.md` records anything a user would notice
- [ ] No API key, hostname, or other credential appears in the diff or in test fixtures
