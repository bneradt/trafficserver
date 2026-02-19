# Generate a Git Commit

When creating a commit for a patch:

- Run `cmake --build build --target format` if formatting has not been run since the last edits.
- Write a short one-line summary (target: under ~60 characters).
- Add a concise body (1-3 short paragraphs) focused on why the change is needed and how it resolves the issue.
- Keep implementation detail high-level; the patch contains exact code changes.
- If applicable, end with: `Fixes: #<issue_number>`.

Do not push unless explicitly asked.
