---
name: create-pr
description: Create a GitHub pull request from the current branch using the latest commit message for title/body, assign to the current user, apply relevant labels, set milestone 11.0.0, and return the PR link.
---

# Create PR

When asked to create a PR for the current branch:

1. Use the latest commit message subject as the PR title.
2. Use the latest commit message body as the PR description.
3. Assign the PR to yourself (`--assignee @me`).
4. Apply appropriate labels for the change area and test impact.
5. Set the milestone to `11.0.0` unless told otherwise.
6. Return a clickable PR link.

## Commands

```bash
subj=$(git log -1 --pretty=%s)
body=$(git log -1 --pretty=%b)
gh pr create \
  --base master \
  --head "$(git config user.name | tr '[:upper:]' '[:lower:]')":"$(git branch --show-current)" \
  --title "$subj" \
  --body "$body" \
  --assignee @me \
  --milestone "11.0.0"
```

After creating the PR, add labels:

```bash
gh pr edit --add-label "<label1>" --add-label "<label2>"
```
