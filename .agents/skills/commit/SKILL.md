---
name: commit
description: Write an ATS-oriented git commit message and verify formatting before committing.
---

# Generate a Git Commit

When creating a commit for a patch:

- Run `cmake --build build --target format` if formatting has not been run since the last edits.
- Write a short one-line summary (target: under ~60 characters).
- Add a concise body (1-3 short paragraphs) focused on why the change is needed and how it resolves the issue.
- Wrap all commit message lines at 72 characters or less.
- Use real newlines in the commit body; never embed literal `\n` sequences.
- Prefer writing the message to a temporary file or heredoc and passing it via `git commit -F <file>` to preserve wrapping.
- Keep implementation detail high-level; the patch contains exact code changes.
- If applicable, end with: `Fixes: #<issue_number>`.

Also, make the sentences in the commit full sentences with referencing the
patch as the subject explicitly. That is, I don't like this:

    Add pre-transaction LogAccess path for malformed h2 request headers and
    emit a best-effort access log entry before resetting the stream.

Rather, word like this:

    This adds pre-transaction LogAccess path for malformed h2 request headers
    and emits a best-effort access log entry before resetting the stream.

Do not push unless explicitly asked.
