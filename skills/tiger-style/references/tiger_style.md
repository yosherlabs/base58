# TigerStyle Reference (Condensed)

Source URL:
https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md

Use this reference when the task explicitly requests TigerStyle or TigerBeetle-aligned coding style.

## 1) Priority Order

Apply this order for all decisions:

1. Safety
2. Performance
3. Developer experience

Treat style as design quality, not cosmetic formatting.

## 2) Safety Rules

- Use simple, explicit control flow.
- Avoid recursion.
- Put hard limits on loops, queues, and internal work.
- Fail fast when invariants are violated.
- Use explicit-sized types such as `u32` where practical.
- Assert preconditions, postconditions, invariants, and boundary assumptions.
- Aim for high assertion density.
- Add paired assertions at independent boundaries.
- Split compound assertions into smaller assertions.
- Assert compile-time invariants when available.
- Assert positive and negative space.
- Handle all signaled errors.
- Keep memory behavior predictable in critical paths.
- Minimize scope of variables and keep checks near use.
- Keep each function under 70 lines.
- Compile with strict warnings and address warnings early.
- Do not let external events own control flow; process work at controlled pace.

## 3) Control Flow and Conditions

- Prefer nested `if/else` trees over dense compound conditions when clarity improves.
- Prefer positive invariant statements.
- Keep explicit `else` branches where they document negative space.
- Use braces consistently except for truly simple single-line forms.

## 4) Performance Rules

- Do performance thinking in the design phase.
- Make back-of-the-envelope estimates for:
  - network bandwidth/latency
  - disk bandwidth/latency
  - memory bandwidth/latency
  - CPU throughput/latency
- Optimize slowest resources first, adjusted for frequency.
- Distinguish control plane from data plane.
- Batch operations to amortize fixed costs.
- Keep hot loops explicit and easy for humans to reason about.

## 5) Developer Experience Rules

### Naming

- Pick precise nouns and verbs.
- Use snake_case for files, functions, and variables.
- Avoid abbreviations unless domain-typical and unambiguous.
- Preserve acronym capitalization consistently.
- Include units or qualifiers in variable names.
- Keep related names symmetrical when possible.
- Avoid overloaded terms with multiple meanings.

### File and declaration order

- Prefer top-down readability.
- Place important entry points near top where practical.
- Keep ordering consistent and intentional.

### Comments and rationale

- Explain why, not only what.
- Write comments as clean sentences.
- Document test goal and method before dense test bodies.

## 6) State and Memory Hygiene

- Avoid duplicate state and unnecessary aliases.
- Pass large by-value data as immutable references/pointers when copy risk is high.
- Construct large objects in place where language permits.
- Group allocation/deallocation visually to expose leaks.
- Watch for under-filled buffers and stale bytes.

## 7) Off-by-One Discipline

- Treat index, count, and size as distinct conceptual types.
- Convert explicitly and carefully between them.
- Use explicit division semantics when rounding behavior matters.

## 8) Formatting and Limits

- Indent with 4 spaces.
- Keep line length <= 100 columns.
- Use the language formatter where available.
- Keep functions <= 70 lines.

## 9) Dependencies and Tooling

- Prefer minimal dependencies.
- Standardize on a small toolchain.
- Favor predictable, portable tooling over convenience sprawl.

## 10) Practical TigerStyle Review Checklist

Use this checklist for reviews and refactors:

- Are loops and queues bounded?
- Are errors explicitly handled?
- Are assertions present at function boundaries?
- Are paired assertions present at independent boundaries?
- Are defaults made explicit at call sites?
- Are names specific and unit-qualified where needed?
- Is function length under 70 lines?
- Is line length <= 100?
- Are variables scoped tightly near use?
- Is resource usage estimated and batched?
- Are tests covering valid and invalid spaces?
- Is there any avoidable technical debt left in place?

## 11) Application Note

When exact Zig constructs are unavailable, preserve intent:

- Make assumptions explicit.
- Keep bounds and assertions visible.
- Prefer predictable control flow over concise cleverness.
