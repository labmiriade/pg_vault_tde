# Contributing

Thanks for your interest in pg_vault_tde. The canonical repository lives on an
internal Bitbucket instance; this GitHub repository is a mirror that also
accepts external contributions. Here's what happens after you open a PR:

1. Open your pull request here against `develop` (or `main` for release-only
   fixes) as usual.
2. A bot mirrors your branch to our internal Bitbucket repository as
   `github-pr/<PR number>-<slug>` and leaves a comment here confirming it.
3. A maintainer reviews it internally using the same standards as any other
   contribution, and may ask for changes — just push more commits to your
   branch and they'll be re-mirrored automatically.
4. Once merged internally (with a merge commit, so your original commits are
   preserved), the next sync to GitHub carries those exact commits into
   `develop`/`main`. GitHub then recognizes them and **closes this PR
   automatically** as merged.

If your PR is squashed instead of merged internally for any reason, it won't
auto-close — a maintainer will close it manually with a reference to the
corresponding Bitbucket commit.

No separate GitHub account setup is required on your side; just open the PR
and follow the discussion there.
