# rename_default_branch

This will find all projects accessible by the API token, filterable by namespace and project. It will skip any repository that already had a `main` branch.

- Create a new branch `main` copied from `master`.
- Copy branch protection rules from `master` to `main`.
- Re-target any pull requests from `master` to `main`.
- Update any scheduled pipelines referencing `master`.
- Update any webhooks referencing `master`.
- Delete the `master` branch.
- Create a new branch protection rule for `master` preventing any future pushes.

 **NOTE:** For a premium subscriber it'd be required to implement a few more parts of the protection API. This will not copy user/group protections.

## Setup

### Installation

```
$ pipenv install
```

### Authentication

Create a gitlab personal access token with `api` scope and export it into the env:

```
$ export GITLAB_TOKEN=...
```

## Usage

```
$ pipenv run python rename_default_branch.py --dry-run
```