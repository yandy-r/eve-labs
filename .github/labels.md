# GitHub Labels for eve-labs

Apply these labels to keep issues and pull requests consistently categorized. Prune and
customize for your project. `area:` labels are project-specific; add them yourself.

## Label Families

| Label | Family | Description |
|---|---|---|
| `type:bug` | type | Something isn't working |
| `type:feature` | type | New functionality |
| `type:docs` | type | Documentation only |
| `type:refactor` | type | No functional changes |
| `type:perf` | type | Performance improvement |
| `type:test` | type | Adding or fixing tests |
| `type:build` | type | Build system or dependencies |
| `type:ci` | type | CI/CD pipeline changes |
| `type:chore` | type | Routine maintenance |
| `type:migration` | type | Migration or upgrade |
| `type:security` | type | Security fix or audit |
| `priority:critical` | priority | Must fix immediately |
| `priority:high` | priority | Fix in current milestone |
| `priority:medium` | priority | Fix in next milestone |
| `priority:low` | priority | Nice to have |
| `status:needs-triage` | status | Awaiting review |
| `status:in-progress` | status | Actively being worked on |
| `status:blocked` | status | Blocked by external factor |
| `status:needs-info` | status | Waiting for more information |
| `good first issue` | standalone | Suitable for newcomers |
| `help wanted` | standalone | Extra attention needed |
| `duplicate` | standalone | Already reported |
| `wontfix` | standalone | Intentionally not addressed |
| `regression` | standalone | Broke something that worked |

## Apply with `gh label create`

```bash
gh label create "type:bug"       --color "d73a4a" --description "Something isn't working"
gh label create "type:feature"   --color "a2eeef" --description "New functionality"
gh label create "type:docs"      --color "0075ca" --description "Documentation only"
gh label create "type:refactor"  --color "e4e669" --description "No functional changes"
gh label create "type:perf"      --color "f9d0c4" --description "Performance improvement"
gh label create "type:test"      --color "bfd4f2" --description "Adding or fixing tests"
gh label create "type:build"     --color "c5def5" --description "Build system or dependencies"
gh label create "type:security"  --color "ee0701" --description "Security fix or audit"
gh label create "priority:critical" --color "b60205" --description "Must fix immediately"
gh label create "priority:high"     --color "e11d48" --description "Fix in current milestone"
gh label create "priority:medium"   --color "f97316" --description "Fix in next milestone"
gh label create "priority:low"      --color "fef08a" --description "Nice to have"
gh label create "status:needs-triage"  --color "ededed" --description "Awaiting review"
gh label create "status:in-progress"   --color "0e8a16" --description "Actively being worked on"
gh label create "status:blocked"       --color "d93f0b" --description "Blocked by external factor"
gh label create "good first issue"  --color "7057ff" --description "Suitable for newcomers"
gh label create "help wanted"       --color "008672" --description "Extra attention needed"
```

> **Note:** Prune and customize for your project. `area:` labels are project-specific;
> add them yourself (e.g., `area:auth`, `area:cli`, `area:api`).
