---
name: tiger-style
description: >-
  Enforce TigerStyle engineering standards with safety-first constraints,
  performance-first design sketches, and developer-experience naming and
  structure rules. Use when Codex must design, implement, refactor, or review
  code to match TigerBeetle style, including bounded control flow,
  assertion-driven correctness, explicit options and types, strict size limits,
  and zero-technical-debt decision-making.
---

# Tiger Style

## Overview

Apply TigerStyle in this priority order:

1. Safety
2. Performance
3. Developer experience

Treat readability as table stakes in service of those goals.

## Workflow

1. Classify the task as one of: design, implementation, refactor, review, or test planning.
2. Load only the needed sections from `references/tiger_style.md`.
3. Apply non-negotiable rules first, then language-specific style details.
4. Explain why each non-obvious decision exists.
5. End with a short TigerStyle compliance summary.

## Non-Negotiable Rules

- Keep control flow simple and explicit.
- Avoid recursion.
- Put an upper bound on loops, queues, and work units.
- Use fail-fast behavior for invariant violations.
- Assert preconditions, postconditions, and invariants aggressively.
- Split compound assertions into focused assertions.
- Assert both positive space and negative space.
- Prefer compile-time assertions for design invariants when possible.
- Handle all operating errors explicitly.
- Prefer explicit options at every call site over hidden defaults.
- Keep functions short; target a hard limit of 70 lines.
- Keep line length at or below 100 columns.
- Use fixed-size integer types where practical.
- Minimize variables in scope and declare near first use.
- Avoid duplicate state and unnecessary aliases.
- Avoid dynamic allocation after initialization in critical paths.
- Prefer zero technical debt decisions when tradeoffs are known.

## Task Guidance

### Implementation

- Sketch resource costs before coding: network, disk, memory, CPU.
- Batch work to amortize fixed costs.
- Keep control plane and data plane boundaries explicit.
- Push conditionals up and loops down where it simplifies reasoning.
- Keep leaf helpers pure where practical.

### Refactor

- Shrink function length and branch complexity first.
- Remove ambiguous names, abbreviations, and context-dependent terms.
- Replace broad implicit behavior with explicit parameters/options.
- Move checks closer to use to reduce place-of-check to place-of-use gaps.

### Review

- Report findings in order: safety, performance, then developer experience.
- Flag unbounded loops, implicit defaults, missing assertions, and unchecked errors.
- Flag naming that hides units, meaning, or control/data flow intent.
- Propose concrete, testable fixes.

### Tests

- Test valid and invalid space.
- Test boundary transitions where values become invalid.
- Add paired checks around write/read or encode/decode boundaries.
- Prefer deterministic tests with explicit limits and assertions.

## Language Mapping

- Map Zig-specific guidance to equivalent constructs in the target language.
- Preserve intent when exact constructs do not exist.
- Keep explicitness over brevity when there is conflict.

## Output Contract

When the user asks for TigerStyle conformance, include:

1. Applied rules
2. Detected violations or risks
3. Changes made (or recommended)
4. Remaining gaps
5. Suggested tests

## Resources

- Primary reference: `references/tiger_style.md`
- Canonical source URL is recorded in the reference file.
