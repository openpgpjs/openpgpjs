# Contributing to OpenPGP.js

Please take a moment to review this document in order to make the contribution process easy and effective for everyone involved.

Following these guidelines helps to communicate that you respect the time of the developers managing and developing this open source project. In return, they should reciprocate that respect in addressing your issue, assessing changes, and helping you finalize your pull requests.

As for everything else in the project, the contributions are governed by our [Code of Conduct](https://github.com/openpgpjs/openpgpjs/blob/main/CODE_OF_CONDUCT.md).

- [Contributing to OpenPGP.js](#contributing-to-openpgpjs)
  - [Coding conventions // TODO: check if they have](#coding-conventions--todo-check-if-they-have)
  - [Getting started](#getting-started)
    - [Decide what you want to work on](#decide-what-you-want-to-work-on)
    - [Notify your interest](#notify-your-interest)
    - [Setting up the project in your local machine](#setting-up-the-project-in-your-local-machine)
  - [Pull requests](#pull-requests)
    - [I have submitted my PR, what are the next steps?](#i-have-submitted-my-pr-what-are-the-next-steps)
  - [Bug reports](#bug-reports)
  - [Release process](#release-process)
  - [Communication](#communication)
  - [Thank you // maybe??](#thank-you--maybe)

## Coding conventions // TODO: check if they have

## Getting started

### Decide what you want to work on

If you are looking for something to work on, we try to maintain a list of issues that should be suitable for first time contributions, they can be found tagged [`good-first-issue`](https://github.com/openpgpjs/openpgpjs/labels/good-first-issue). You can also look through our issues and pick some you like.

### Notify your interest

Please let us know you want to work on it so we can avoid multiple people working on the same issue. 
// TODO: How?

**Please ask first** before embarking on any significant pull request (e.g. implementing features, refactoring code), otherwise you risk spending a lot of time working on something that the project's developers might not want to merge into the project.

### Setting up the project in your local machine

1. [Fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) the project, clone your fork, and configure the remotes:

    ```bash
    # Clone your fork of the repo into the current directory
    git clone https://github.com/<your-username>/<repo-name>
    
    # Navigate to the newly cloned directory
    cd <repo-name>
    
    # Assign the original repo to a remote called "upstream"
    git remote add upstream https://github.com/openpgpjs/<repo-name>
    ```

2. Install dependencies with your preferred package manager:
   ```bash
   npm install
   ```
// TODO: do they want other package managers here as well?

3. Create a new topic branch (off the main project development branch) to contain your feature, change, or fix:

   ```bash
   git checkout -b <topic-branch-name>
   ```

// Coding conventions?

4. Please follow our commit message conventions while committing to your branch // TODO: review if they have commit conventions

5. Make sure to update, or add to the tests when appropriate. Run `npm test` to check that all tests pass after you've made changes. Look for a `Testing` section in the project’s README for more information.

6. If you added or changed a feature, make sure to document it accordingly in the `README.md` file.

## Pull requests

Good pull requests - patches, improvements, new features - are a fantastic help. They should remain focused in scope and avoid containing unrelated commits.

If you have never created a pull request before, welcome :smile: [Here is a great tutorial](https://app.egghead.io/playlists/how-to-contribute-to-an-open-source-project-on-github) on how to create a pull request.

1. Push your topic branch up to your fork:

   ```bash
   git push origin <topic-branch-name>
   ```

2. Update your branch to the latest changes in the upstream main branch. You can do that locally with:

   ```bash
   git pull --rebase upstream main
   ```

3. [Open a Pull Request](https://help.github.com/articles/using-pull-requests/) with a clear title and follow the instructions specified in the Pull Request template.

10. Check if the Github Actions workflows have passed. Address the errors if they have not.

**IMPORTANT**: By submitting a patch, you agree to license your work under the same license as that used by the project.

### I have submitted my PR, what are the next steps?

First of all, thank you for your contribution! Sit and relax. Someone from the team will review your PR and respond with comments as soon as possible (usually within two weeks // TODO: what is an acceptable time frame for them?). Once you have addressed all the comments, your PR will be approved and merged.

## Bug reports

First things first: **Do NOT report security vulnerabilities in public issues!** Please, disclose responsibly following the instructions detailed in [SECURITY.md](https://github.com/openpgpjs/openpgpjs/blob/main/SECURITY.md). Thank you.

A bug is a _demonstrable problem_ that is caused by the code in our repository.
Good bug reports are extremely helpful - thank you!

Guidelines for bug reports:

1. **Use the GitHub issue search** &mdash; check if the issue has already been reported.

2. **Check if the issue has been fixed** &mdash; try to reproduce it using the latest `main` branch in the repository.

3. **Isolate the problem** &mdash; ideally create a reduced test case.

A good bug report shouldn't leave others needing to chase you up for more information. Please try to be as detailed as possible in your report. What is your environment? What steps will reproduce the issue? What OS experiences the problem? What would you expect to be the outcome? All these details will help people to fix any potential bugs.

To create a new bug report, go to Issues, and select the Bug Report template.

## Communication

Link here the gitter and github discussions?

## Thank you // maybe??

Special thanks to [Hoodie](https://github.com/hoodiehq/hoodie) for the great CONTRIBUTING.md template.



TODO: read here and see if we can get ideas https://github.com/kubernetes/community/blob/master/contributors/guide/non-code-contributions.md