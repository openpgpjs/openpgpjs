# Guide for New Contributors <!-- omit from toc -->

👋 **First off! Hello, and a warm welcome to the OpenPGP.js project!**

We’re delighted that you’re interested in participating, and we want to make it as pleasant and simple as we can, whether you want to send a one-off pull request or you want to become part of the team in the long run.

**If you’re new here and interested in any form of contribution, this guide is for you.**

**Contents:**

- [Who are we and what is OpenPGP.js?](#who-are-we-and-what-is-openpgpjs)
- [Who can Contribute?](#who-can-contribute)
- [How do you get Started?](#how-do-you-get-started)
  - [Get Familiar with the Basic Principles](#get-familiar-with-the-basic-principles)
  - [Take OpenPGP.js for a Spin](#take-openpgpjs-for-a-spin)
  - [Getting your Bearings in the OpenPGP.js Project](#getting-your-bearings-in-the-openpgpjs-project)

## Who are we and what is OpenPGP.js?

[OpenPGP.js](https://openpgpjs.org/) is a JavaScript implementation of the [OpenPGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) protocol. It implements [RFC4880](https://tools.ietf.org/html/rfc4880) and parts of [RFC4880bis](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10).

This project aims to provide an Open Source OpenPGP library in JavaScript so it can be used on virtually every device. Instead of other implementations that are aimed at using native code, OpenPGP.js is meant to bypass this requirement (i.e. people will not have to install gpg on their machines in order to use the library). The idea is to implement all the needed OpenPGP functionality in a JavaScript library that can be reused in other projects that provide browser extensions or server applications. It should allow you to sign, encrypt, decrypt, and verify any kind of text - in particular e-mails - as well as managing keys.

This project is maintained by [Proton Mail](https://proton.me/blog/openpgpjs-email-encryption) and is supported by the EU’s Horizon 2020 programme.

OpenPGP.js is built by [a variety of people](https://github.com/orgs/openpgpjs/people), but there are a couple you’ll run into more frequently, and who can be considered the core of the project:

- [twiss](https://github.com/twiss) (Daniel Huigens)
- [larabr](https://github.com/larabr)

## Who can Contribute?

While this _is_ cryptography-heavy JavaScript software, and those skills are especially relevant, an Open Source project such as this one has a wide range of needs, and there are a lot of opportunities to help:

- There are usually some non-cryptography related JS (and TS!) tasks
- You can expand or improve the test suite
- You can take the project for a test drive and update the dev setup documentation for your platform (see [CONTRIBUTING.md](/CONTRIBUTING.md))
- You can improve the various documentation resources in general, for example by looking for [documentation issues](https://github.com/openpgpjs/openpgpjs/issues?q=is%3Aissue+is%3Aopen+label%3ADocumentation), or just picking something to expand upon, edit or check for typos
- You can improve the build process
- You can do manual tests and UI/UX evaluations of features or tools and help improve their usability
- You can improve or maintain [our website](https://openpgpjs.org/)
- You can evangelize for the project: present or talk about OpenPGP.js in your company, local tech meetup, youtube channel, or similar circles
- You can answer questions on our [Gitter](https://gitter.im/openpgpjs/openpgpjs) or our [GitHub discussions](https://github.com/openpgpjs/openpgpjs/discussions)

## How do you get Started?

### Get Familiar with the Basic Principles

Depending on your background and contribution to the project, it might be useful to read up on the basics of how online cryptography and PGP work:

- [A quick intro to PGP](https://proton.me/blog/what-is-pgp-encryption), covering public and private keys, symmetric and asymmetric keys, signatures and address verification. This article is by ProtonMail, [the primary maintainers of this project](https://proton.me/blog/openpgpjs-email-encryption).
- A more general [video](https://www.youtube.com/watch?v=NuyzuNBFWxQ) on the basic cryptographic principles frequently used online, such as hashing, salting, encryption, symmetric and asymmetric keys, and signing.

### Take OpenPGP.js for a Spin

This involves getting things running on your machine and trying out the features. Thankfully, OpenPGP.js doesn’t have a lot of prerequisites:

1. You need a [current version of node.js](https://nodejs.org/en/about/previous-releases) installed
2. Install depencencies with `$ npm i`

That’s it. Now you can run the node tests:

```bash
npm test
```

You can also run the tests in a browser with:

```bash
npm run browsertest
```

And that’s your dev environment sorted.

### Getting your Bearings in the OpenPGP.js Project

We’ve got a bunch of helpful resources you might be interested in:

- There’s a [public gitter chat](https://app.gitter.im/#/room/#openpgpjs_openpgpjs:gitter.im), which is a good place for establishing first contact with the project
- **Our [Guide for Contributors](/CONTRIBUTING.md), which details  topics such as project processes, code and commit conventions, expectations for PRs, as well as documentation on dev setup and testing.**
- The [Code of Conduct](/CODE_OF_CONDUCT.md) we operate by, and which you are also expected to adhere to

And of course our [GitHub issues](https://github.com/openpgpjs/openpgpjs/issues), where you can find tasks to take on. We try to have some [Good First Issues](https://github.com/openpgpjs/openpgpjs/labels/good%20first%20issue) for newcomers in place, but there might not always be some available.

In any case, it’s always a good idea to [have a chat with us](https://app.gitter.im/#/room/#openpgpjs_openpgpjs:gitter.im) before you start any work.

All that’s left here is to thank you for your time and interest, and we hope you’ll join us on our quest for better Open Source cryptography on the web! 🚀

👋


