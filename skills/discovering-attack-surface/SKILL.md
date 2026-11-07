---
name: discovering-attack-surface
description: Map what the target is and where untrusted input enters, before any scanning. Produces surface.json and the set of modules the target can actually support. Use at the start of a security assessment, when /sec-discover or /sec-start runs, or when a scan needs to know which modules apply.
version: 1.0.0
---

# Discovering the attack surface

Read `sec-protocol` first.

Burp models an application as a graph of locations; ZAP builds a Sites Tree. This is the
static equivalent. **Findings without a mapped surface are guesses** — you cannot say a
guard is missing until you know which routes exist.

## Run it

```bash
node <ai-sec>/bin/sec.mjs discover [target] --slug <slug>
```

This writes `.sec/<slug>/surface.json` and prints the summary. It detects frameworks and
ORMs by how a dependency is actually named (quoted in a manifest, required, imported), not
by a bare word, so `req.query.next` does not become "this is Next.js".

## Then do what the command cannot

The command reports structure. You interpret it.

### 1. Check the detection against the repo
Open two or three of the files it drew conclusions from. The detector is regex-based and
will be wrong sometimes. Correct `surface.json` rather than carrying a wrong premise into
every later step.

### 2. Find the trust boundaries
The command lists routes, guards and insertion points. It cannot tell you where trust
changes hands. Identify:
- which routes are public, which require a session, which require a role
- where data crosses from the user to the database, to the shell, to another service
- which third parties the app calls, and what it trusts from their responses

### 3. Read the signals, not just the counts

| Signal | What it means | Act on it |
|---|---|---|
| Routes present, no guards detected | Either authorization lives somewhere this pass did not read, or it is missing | Find the enforcement point by hand before M5 runs. If there is none, that is the headline finding. |
| `multi_tenant` markers present | Every query touching tenant data needs a predicate | M8's tenant isolation check becomes the priority |
| `raw-sql` in the ORM list | There is a path around the query builder | M1 and M6 matter more than usual |
| No auth detected but routes exist | A hand-written guard, or none | Confirm which; `custom-middleware` is a guess |
| Few files, many routes | Likely a thin layer over something else | Ask where the rest of the system is |

### 4. Record the insertion points
Every place input enters: URL and body parameters, JSON and XML fields, headers, cookies,
path segments, uploads, and anything Base64 or otherwise encoded. These are what later
modules test against, and what a finding's `insertion_point` names.

## Do not

- Do not scan before mapping. A module selected for a target with no inputs for it produces
  a coverage gap nobody can close.
- Do not accept `applicable_modules` without reading it. If it dropped a module the target
  clearly supports, the detector missed something and the gap is silent.
- Do not ask the user what the repo answers. Frameworks, routes and dependencies are read,
  never asked.

## Done when

- `surface.json` exists and you have checked its conclusions against the code.
- You can name where input enters and where authorization is enforced — or state plainly
  that authorization has no single enforcement point, which is itself a finding.
- The module list is agreed, and anything dropped is dropped for a reason you can state.
