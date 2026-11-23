## GitHub agent attribution

Every issue body, pull request body, and GitHub comment an agent writes or edits on Solomon's behalf in this repository ends with this block. Keep the human author identity. Use the actual model, harness, and client. Credit only work performed, include the provider if a model name is ambiguous, and list each review pass. Report the exact checks and observed results above the block. Credit verification to the model that ran the checks.

```text
Sent on behalf of Solomon by <orchestrator model> via <harness> in <client>
Models used:
- Implementation/build: <model> via <harness>, or none
- Test/verification: <model> via <harness> (checks: listed above), or not run
- Review: <model> via <harness> for each pass, or none
```

Every agent-written review comment and review summary on Solomon's behalf also includes `Review by <model> via <harness> in <client>`.
