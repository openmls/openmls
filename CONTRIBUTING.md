# Engineering & Contributing Guidelines

The following is a set of guidelines for contributing to this repository.
These are mostly guidelines, not rules.
Use your best judgement, and feel free to propose changes to this document in a pull request.
The processes described here is not to pester you but to increase and maintain code quality.

Before contributing, please read the [Code of Conduct](https://github.com/openmls/openmls/CODE_OF_CONDUCT.md) carefully.

#### Table Of Contents

- [Working with this repository](#working-with-this-repository)
  - [Prioritisation](#prioritisation)
  - [Patches](#patches)
- [Pull Requests](#pull-requests)
  - [PR & Commit Guidelines](#pr--commit-guidelines)
  - [PR Template](#pr-template)
- [Styleguides](#styleguides)
  - [Git Commit Messages](#git-commit-messages)
  - [Rust Styleguide](#rust-styleguide)
  - [Documentation Styleguide](#documentation-styleguide)
- [Reviews](#reviews)
  - [Review Guidelines](#review-guidelines)

## Working with this repository

We use issues to organise and prioritise work items.
If you start working on an issue, assign it to yourself so everyone knows it's being worked on.
Unassign yourself if you stop working on it and leave a comment why you stopped.

After picking up an issue create a branch.
There can be any number of branches and pull request for one issue.
But make sure that each issue is clearly linked to the pull request.
There must be one pull request that closes the issue.
If there are multiple PRs for an issue, make sure this is clear in the pull request.

### Prioritisation

Issue priorities are reflected with labels.

| Label | Description                              |
| :---- | :--------------------------------------- |
| P1    | must be addresses asap                   |
| P2    | pick up next                             |
| P3    | low-priority item                        |
| P4    | wontfix unless someone contributes a fix |

### Patches

Sometimes, you have to work on another crate (e.g. [hpke-rs](https://crates.io/crates/hpke-rs)) alongside openmls. The 
recommended way to proceed while developing locally is to patch openmls by adding the following to the root [Cargo.toml](./Cargo.toml): 
```toml
[patch.crates-io.hpke-rs]
path = "../hpke-rs" # local path to the project
```
Once you are done with your changes and feel it's ready to be submitted, you will have to make your patch point to a
remote branch in order for the CI to succeed:
```toml
[patch.crates-io.hpke-rs]
git = "https://github.com/my-fork/hpke-rs"
branch = "fix/123"
package = "hpke-rs"
```

## Pull Requests

We use the Github based PR workflow.
When starting to work on an issue create a branch and an according pull request that fixes the issue.
The changeset in a pull requests must not be larger than 1000 lines.
If an issue needs more work than that, split it into multiple pull requests.

Make sure that your PR follows the [template](#pr-template).
After submitting the pull request, verify that all [status checks](https://help.github.com/articles/about-status-checks/) are passing before asking for review.

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.

### PR & Commit Guidelines

- Split out mass-changes or mechanical changes into a separate PR from the substantive changes.
- Separate commits into conceptually-separate pieces for review purposes (even if you then later collapse them into a single changeset to merge), if technically possible.
- Address all comments from previous reviews (either by fixing as requested, or explaining why you haven't) before requesting another review.
- If your request only relates to part of the changes, say so clearly.

### PR Template

- Link to an open issue and assign yourself to the issue and the PR (if possible).
- It must be possible to understand the design of your change from the description. If it's not possible to get a good idea of what the code will be doing from the description here, the pull request may be closed. Keep in mind that the reviewer may not be familiar with or have worked with the code here recently, so please walk us through the concepts.
- Explain what other alternates were considered and why the proposed version was selected.
- What are the possible side-effects or negative impacts of the code change?
- What process did you follow to verify that your change has the desired effects?
  - How did you verify that all new functionality works as expected?
  - How did you verify that all changed functionality works as expected?
  - How did you verify that the change has not introduced any regressions?
  - Describe the actions you performed (including buttons you clicked, text you typed, commands you ran, etc.), and describe the results you observed.
- If this is a user-facing change please describe the changes in a single line that explains this improvement in terms that a library user can understand.

## Styleguides

### Git Commit Messages

- Use the present tense
- Use the imperative mood
- Limit the first line to 80 characters
- Reference issues and pull requests liberally after the first line
- If the patch is of nontrivial size, point to the important comments in the non-first lines of the commit message.

### Rust Styleguide

Use `rustfmt` on everything.
The CI will check that the patch adheres to the `rustfmt` style.

### Documentation Styleguide

Use [rustdoc](https://doc.rust-lang.org/rustdoc/index.html) comments on files and functions.
It is mandatory on public functions and encouraged on internal functions.

## Reviews

As a reviewer always keep in mind the following principles

- Reviewing code is more valuable than writing code as it results in higher overall project activity. If you find you can't write code any more due to prioritizing reviews over coding, let's talk.
- You should respond to a review request within one working day of getting it, either with a review, a deadline by which you promise to do the review, or a polite refusal. If you think a patch is lower priority than your other work communicate that.

### Review Guidelines

- Check that issue is assigned and linked.
- Commit title and message make sense and says what is being changed.
- Check that the PR applies cleanly on the target branch.
- Check new files for license and administrative issues.
- Check out code changes
  - Run automated tests
  - Manually verify changes if possible
- Code review
  - Does the change address the issue at hand?
  - Is the code well documented?
  - Do you understand the code changes?
    - If not, add a comment. The PR can't be accepted in this stage.
  - Is the public API changed?
    - Are the changes well documented for consumers?
    - Do the changes break backwards compatibility?
    - Is the new API sensible/needed?
  - Is the code maintainable after these changes?
  - Are there any security issues with these changes?
  - Are all code changes tested?
  - Do the changes effect performance?
  - Look at the interdiff for second and subsequent reviews.
- Ask if more information is needed to understand and judge the changes.
