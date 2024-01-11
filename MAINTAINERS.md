# Maintainers Guide <!-- omit in toc -->

This document is intended for the active maintainers of the project. Its purpose is to help them offload knowledge and decision-making overhead into formalised processes, or a set of concrete suggestions.

Maintainers, old and new, are encouraged to read and refer back to this guide whenever there are doubts about how to run the project, and also to record and additions and changes to project processes.

**Project processes**
- [Issue Triage](#issue-triage)
  - [Step 1: Type the Issue](#step-1-type-the-issue)
    - [`Support` for support requests](#support-for-support-requests)
    - [`Wontfix` for misplaced or irrelevant issues](#wontfix-for-misplaced-or-irrelevant-issues)
    - [`Need more info` for incomplete issues](#need-more-info-for-incomplete-issues)
    - [`Stale` for abandoned issues](#stale-for-abandoned-issues)
    - [`Bug` for things that don’t work as intended](#bug-for-things-that-dont-work-as-intended)
    - [Good First Issues and Help Wanted Issues](#good-first-issues-and-help-wanted-issues)
      - [Criteria for a `Help wanted` Issue](#criteria-for-a-help-wanted-issue)
      - [Criteria for a `Good first issue`](#criteria-for-a-good-first-issue)
    - [Other Issue Types](#other-issue-types)
  - [Step 2: Prioritize the Issue](#step-2-prioritize-the-issue)
    - [`priority/critical-urgent`](#prioritycritical-urgent)
    - [`priority/important-soon`](#priorityimportant-soon)
    - [`priority/important-longterm`](#priorityimportant-longterm)
    - [`priority/backlog`](#prioritybacklog)
  - [Step 3: Assign the Work](#step-3-assign-the-work)
  - [Step 4: Follow up](#step-4-follow-up)
- [Release process](#release-process)


## Issue Triage

<details>
<summary>Source</summary>
The Issue Triage section of the guide was heavily inspired by and occasionally uses the excellent <a href="https://github.com/kubernetes/community/blob/master/contributors/guide/issue-triage.md">Kubernetes Contributors Guide</a>.
</details>

**Maintainers are encouraged to regularly triage incoming issues and PRs**, which means:
- A short response to the issue author acknowledging that the issue was seen
- Evaluating and labelling the issue according to type, priority and urgency
- Assigning the issue/PR to a contributor or maintainer for work or review

Triage can happen asynchronously and continuously, or in regularly scheduled meetings.

**Benefits of triaging are:**
- Maintaining project momentum
- Engagement of contributors by increasing responsiveness
- Prevents piling up of issues and work
- Prevents issues and the project itself becoming stale
- Provides structure and an opportunity for collaborative decision-making with regards to the project trajectory and roadmap

It can be beneficial to have triage be part of already existing regular meetings, and if the volume of incoming issues requires it, have a regular, public triage meeting. If there is a regular meeting, make sure it is added here and in the [CONTRIBUTING.md](/CONTRIBUTING.md). Also consider adding it to the [NEW-CONTRIBUTORS.md](/NEW-CONTRIBUTORS.MD) and explicitly invite new and prospective contributors to listen in or participate. This will give interested people a plannable, social opportunity to meet the maintainers and gain insight into the project, with both a low barrier to entry for the new contributors and a low amount of additional effort for the maintainers.

### Step 1: Type the Issue

Issues can be of various types, some of which have labels:

#### `Support` for support requests

Support requests, eg. issues that are not bugs and exclusively concern the usage of the code as it is, will be converted in to a discussion and closed.

Here is [an example](https://github.com/openpgpjs/openpgpjs/issues/1661) of this occuring.

If you find yourself doing this a lot, your `.github/ISSUE_TEMPLATE` needs improvement. The template should be effectively guiding people in need of support to the discussions and away from the issues.

If you realise that the question is a duplicate of an existing discussion, and you can easily find that discussion, it’s worth linking to the existing one instead of creating a new one.

If questions are frequently asked, they might be a frequently asked question! Consider adding the solution to the documentation, Wiki or FAQ, whichever applies and is easily discoverable.

#### `Bug` for things that don’t work as intended

1. Assuming this is not or no longer a `Need more info` issue, attempt to reproduce the bug
   1. Search for duplicates, if one exists, point the current issue there, and close the new one
   2. If you can reproduce it and there are no duplicates, prioritize it and add the `Bug` label
      1. If you need more info before this issue becomes actionable despite being able to reproduce it, prod the author and add a `Need more info` label
   3. If you can’t reproduce it, contact the author with the reason, and add a `Need more info` to the `Bug` label
      1. If the issue cannot be reproduced by anyone other than the author, agree with them that the issue should be closed

As with regular `Need more info` issues, `Need more info` + `Bug` issues are also subject to the [Abandoned/Stale](#abandonedstale) rule above, and should be closed after a set period of time.

#### `Wontfix` for misplaced or irrelevant issues

These are issues that pertain to other projects but have landed here, usually because the poster has no insight into the source of the issue, and the source is actually a dependency.

If you can, close the issue with a comment that points the poster to the correct repo.

#### `Need more info` for incomplete issues

These are issues that seem worthwhile, but are not yet actionable. Give it the `Need more info` label and prod the author for that info.

#### `Stale` for abandoned issues

These are usually `Need more info` issues where the original author does not respond within a sensible time frame (say, a month. People are busy). These are good candidates for a Github bot to manage for you.

Here’s [an example](https://github.com/openpgpjs/openpgpjs/issues/883) of an issue that was manually closed after the author not responding for a year.

#### Good First Issues and Help Wanted Issues

To identify issues that are specifically groomed for new contributors, we use the `Good first issue` label.

As to the difference between `Help wanted` and `Good first issue`:

- a `Good first issue` always also implies `Help wanted` from outside the project
- but `Help wanted` does not necessarily mean it’s a `Good first issue`. Might be really tricky but none of the current maintainers has the resources to tackle it

##### Criteria for a `Help wanted` Issue

- **Clear Task:** The task is agreed upon and does not require further discussions in the community. Call out if that area of code is untested and requires new fixtures.

- **Goldilocks priority:** The priority should not be so high that a core contributor should do it, but not too low that it isn't useful enough for a core contributor to spend time reviewing it, answering questions, helping get it into a release, etc.

- **Up-To-Date:** Often these issues become obsolete and have already been completed, are no longer desired, no longer make sense, or have changed priority or difficulty.

##### Criteria for a `Good first issue`

Items marked with the `Good first issue` label are intended for first-time contributors. It indicates that maintainers will _proactively_ keep an eye out for the corresponding pull requests and shepherd them along.

New contributors should not be left to find an approver, ping for reviews, or identify that their build failed due to a flake. It is important to make new contributors feel welcome and valued. We should assure them that they will have an extra level of help with their first contribution.

All `Good first issue` items need to follow the guidelines for help wanted items in addition to meeting the following criteria:

- **No Barrier to Entry:** The task is something that a new contributor can tackle without advanced setup or domain knowledge. This often means improving documentation, tests or working on small, peripheral, testable bugs or features. Tasks that are similar to work that has already been completed are good candidates.

- **Solution Explained:** The recommended solution is clearly described in the issue. There are acceptance criteria defined in the issue.

- **Provides Context:** If background knowledge is required, this should be explicitly mentioned and a list of suggested readings included.

- **Gives Examples:** If possible, link to examples of similar implementations so new contributors have a reference guide for their changes.

- **Identifies Relevant Code:** The relevant code and tests to be changed should be linked in the issue.

- **Ready to Test:** There should be existing tests that can be modified, or existing test cases fit to be copied. If the area of code doesn't have tests, before labeling the issue, add a test fixture. This prep often makes a great help wanted task!

Maintainers are encouraged to invest the extra effort to write and shepherd along these issues and PRs, since onboarding reliable, long-term contributors is an excellent foundation for a sustainable, long-running project that doesn’t burn out the participants.

**Measures can include:**
- Help with the contributor’s dev setup, and if you realise that the onboarding documentation for developers is lacking or out of date, assign their improvement to the new contributor! They probably took notes on the process anyway.
- Proactively watch open first timer-PRs as they change and get in touch if you can save people some time or pain.
- Invite them to meetings and chats
- Rope in other maintainers for a second LGTM at the end
- If the contributor agrees, publicly thank them on whichever channels you broadcast on, as well as in the release notes
- Suggest related `Help wanted` issues

Unless the contributors are insecure about public communication, you’re encouraged to _not_ use private messages as much as possible. Keeping communication public ensures that other people can find and benefit from your discussions in the future.

#### Other Issue Types

There are a variety of additonal labels that are generally self-explanatory, for example:

- `Feature`
- `Documentation`
- `Performance`
- `Testing`
- `Cleanup`
- `Security`
- `Compatibility`

A full list can always be found on the project’s [labels page](https://github.com/openpgpjs/openpgpjs/labels).

### Step 2: Prioritize the Issue

Aside from a type label and the housekeeping labels, issues that are or should become actionable also benefit from having a priority label.

#### `priority/critical-urgent`

Something has gone 💥. Stuff is on fire. Drop what you’re doing and work on this next. Must be in the next planned release, or requires its own release.

#### `priority/important-soon`

Must be staffed and worked on either currently or very soon—ideally in time for the next release. Important, but wouldn't block a release.

#### `priority/important-longterm`

Important over the long term, but may not be currently staffed and/or may require multiple releases to complete. Wouldn't block a release.

#### `priority/backlog`

Would be nice, but no one has the resources to work on it. Good candidates for the `Help wanted` label.

### Step 3: Assign the Work

It should be clear who is responsible for working on an issue once it has been triaged and deemed actionable. This also includes eventual reviews. Ideally don’t assign things to people who aren’t expecting it.

### Step 4: Follow up

- **If no PR is opened on an issue within a month**, a maintainer should contact the assignee and ask them to create a PR or unassign themselves
- **If a PR is ready for review**, find someone to review it within a reasonable amount of time. If you cannot manage a review soon, explain that to the contributor so they’re not left hanging and know what to expect.

## Release process

We keep it simple. We use npm’s `version` command as following:

```sh
npm version {major,minor,patch}
```

(Depending on whether a major, minor or patch release is to be created.) This command will run tests, create a build, publish it to npm, and push to GitHub. 

Additionally, we create a changelog in [GitHub releases](https://github.com/openpgpjs/openpgpjs/releases).
