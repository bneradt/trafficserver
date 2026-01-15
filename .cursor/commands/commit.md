# Generate a git commit

When creating a git commit for a patch:

[ ] Run `cmake --build build --target format` if not run since last change. A pre-commit hook will prevent commits unless the code is formatted.
[ ] Create a short one line summary. Probably less than 60 characters.
[ ] Write a concise couple paragraphs: describe the problem being addressed and the solution.
[ ] Describe the solution at a high level. If people want code details, they can look at the patch.
[ ] If the commit addresses an issue, end with: `Fixes: #<issue_number>`

Do not push the commit unless explicitly asked to.
