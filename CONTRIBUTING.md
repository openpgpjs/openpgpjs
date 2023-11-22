# Contributing to OpenPGP.js

Please take a moment to review this document in order to make the contribution process easy and effective for everyone involved.

Following these guidelines helps to communicate that you respect the time of the developers managing and developing this open source project. In return, they should reciprocate that respect in addressing your issue, assessing changes, and helping you finalize your pull requests.

As for everything else in the project, the contributions are governed by our [Code of Conduct](https://github.com/openpgpjs/openpgpjs/blob/main/CODE_OF_CONDUCT.md).

- [Contributing to OpenPGP.js](#contributing-to-openpgpjs)
  - [Getting started](#getting-started)
    - [Decide what you want to work on](#decide-what-you-want-to-work-on)
    - [Notify your interest](#notify-your-interest)
    - [Setting up the project in your local machine](#setting-up-the-project-in-your-local-machine)
  - [Coding conventions](#coding-conventions)
  - [Commit conventions](#commit-conventions)
  - [Testing](#testing)
  - [Pull requests](#pull-requests)
    - [I have submitted my PR, what are the next steps?](#i-have-submitted-my-pr-what-are-the-next-steps)
  - [Bug reports](#bug-reports)
  - [Non-coding contributions](#non-coding-contributions)
  - [Communication](#communication)
  - [Thank you](#thank-you)

## Getting started

### Decide what you want to work on

If you are looking for something to work on, we try to maintain a list of issues that should be suitable for first time contributions, they can be found tagged [`good-first-issue`](https://github.com/openpgpjs/openpgpjs/labels/good-first-issue). You can also look through our issues and pick some you like. If you're still unsure, please [reach out](#communication) and we would help you with the best of our abilities.

### Notify your interest

Please let us know you want to work on it so we can avoid multiple people working on the same issue. Ideally, notify us by our [Gitter](https://gitter.im/openpgpjs/openpgpjs), but expressing your interest in the issue itself it's also ok.

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

3. Create a new topic branch (off the main project development branch) to contain your feature, change, or fix:

   ```bash
   git checkout -b <topic-branch-name>
   ```

4. Follow our [coding conventions](#coding-conventions) while developing your changes. You can also run `npm run lint` to match our requirements.

5. Write clear and meaningful git commit messages. Please follow our [commit message conventions](#commit-conventions) while committing to your branch.

6. Make sure to update or add to the tests when appropriate. Run the appropriate testing suites to check that all tests pass after you've made changes. You can read about our different types of tests in our [Testing](#testing) section.

7. If you added or changed a feature, make sure to document it accordingly in the [README.md](https://github.com/openpgpjs/openpgpjs/blob/main/README.md) file.

## Coding conventions

We ensure code consistency through our [ESLint config](https://github.com/openpgpjs/openpgpjs/blob/main/.eslintrc.js). You can run `npm run lint` to lint your changes. When in doubt, follow the style of the surrounding code.

## Commit conventions

We follow the seven rules of a great Git commit message, which is extensively described in [this blog post](https://cbea.ms/git-commit/), but in short the principles are:

1. Separate subject from body with a blank line
2. Limit the subject line to 50 characters
3. Capitalize the subject line
4. Do not end the subject line with a period
5. Use the imperative mood in the subject line
6. Wrap the body at 72 characters
7. Use the body to explain what and why vs. how

You can also take a look at our [main branch commits](https://github.com/openpgpjs/openpgpjs/commits/main).

## Testing

We have multiple types of tests. They are located in the root [`/test`](https://github.com/openpgpjs/openpgpjs/tree/main/test) folder.
Before you can run the tests you need to build the project using `npm run build` and this will bundle the project and the tests for it be used in our different testing environments.

**Unit Tests:**
Unit tests are handled by mocha and run inside node, you can run them using this command:

```sh
npm run test
```

**Browser Tests:**
For debugging browser errors, you can run `npm start` and open [`http://localhost:8080/test/unittests.html`](http://localhost:8080/test/unittests.html) in a browser, or run one the following commands:

This will run the tests inside a browser environment:

```sh
   npm run browsertest
```

You can run the tests for multiple headless browsers using KarmaJs:

` npm run test-browser`

If you wanna start the tests using KarmaJs and BrowserStack:
`npm run test-browserstack`

**_NOTE:_**: You need to configure you env with `BROWSER_STACK_ACCESS_KEY` and `BROWSERSTACK_USERNAME` to be able to run the BrowserStack tests.


**Performance:** 
(under `/benchmarks`) to avoid performance regressions, we measure time and memory usage with the following testing suites:

```sh
npm run benchmark-time
npm run benchmark-memory-usage
```

**Typescript definitions**

```sh
npm run test-type-definitions
```

**Coverage**.
We have good numbers but we could always use some help improving them!

```sh
npm run coverage
```

## Pull requests

Good pull requests - patches, improvements, new features - are a fantastic help. They should remain focused in scope and avoid containing unrelated commits.

If you have never created a pull request before, welcome :smile: [Here is a great tutorial](https://app.egghead.io/playlists/how-to-contribute-to-an-open-source-project-on-github) on how to create a pull request.

1. Update your branch to the latest changes in the upstream main branch, solving conflicts if any appear. You can do that locally with:

   ```bash
   git pull --rebase upstream main
   ```

2. Push your topic branch up to your fork:

   ```bash
   git push origin <topic-branch-name>
   ```

3. [Open a Pull Request](https://help.github.com/articles/using-pull-requests/) with a clear title and follow the instructions specified in the Pull Request template. Include a detailed description explaining the reasons for the changes, making sure there is sufficient information for the reviewer to understand your changes.

4. Check if the Github Actions workflows have passed. Address the errors if they have not.

**IMPORTANT**: By submitting a patch, you agree to license your work under the same license as that used by the project.

### I have submitted my PR, what are the next steps?

First of all, thank you for your contribution! Sit and relax. Someone from the team will review your PR and respond with comments as soon as possible (usually within a few weeks). Once you have addressed all the comments, your PR will be approved and merged.

## Bug reports

First things first: please **do not report security vulnerabilities in public issues!** Disclose responsibly following the instructions detailed in [SECURITY.md](https://github.com/openpgpjs/openpgpjs/blob/main/SECURITY.md). Thank you.

A bug is a _demonstrable problem_ that is caused by the code in our repository. Good bug reports are extremely helpful!

Guidelines for bug reports:

1. **Use the GitHub issue search** &mdash; check if the issue has already been reported.

2. **Check if the issue has been fixed** &mdash; try to reproduce it using the latest `main` branch in the repository.

3. **Isolate the problem** &mdash; ideally create a reduced test case.

A good bug report shouldn't leave others needing to chase you up for more information. Please try to be as detailed as possible in your report. What is your environment? What steps will reproduce the issue? What OS experiences the problem? What would you expect to be the outcome? All these details will help people to fix any potential bugs.

To create a new bug report, go to Issues, and select the Bug Report template.

## Non-coding contributions

This list is designed for both new contributors who are seeking a suitable entry point, as well as for existing contributors who would like to do something different. These suggestions do not involve coding directly but may require familiarity with either our codebase or OpenPGP concepts.

- Documentation: typos, document features, add diagrams and visual explanations of concepts
- Answering questions on our [Gitter](https://gitter.im/openpgpjs/openpgpjs) or our [GitHub discussions](https://github.com/openpgpjs/openpgpjs/discussions)
- Evangelism of the project: do demos, write blog posts, talk about the project in meetups

## Communication

Feel free to reach out! You can do so in our [Gitter](https://gitter.im/openpgpjs/openpgpjs) or in our [GitHub discussions](https://github.com/openpgpjs/openpgpjs/discussions)

## Thank you

Thanks to [Hoodie](https://github.com/hoodiehq/hoodie) for inspiring this contributing guide.
