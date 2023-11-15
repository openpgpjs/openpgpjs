# OpenPGP.js Repositories <!-- omit in toc -->

This documents explains all repositories in the OpenPGP.js organization and how they relate to each other.

**Table of Contents**
- [Forks](#forks)
- [Repo Dependency Chart](#repo-dependency-chart)

## Forks
You will notice a large number of forked projects that are dependencies of OpenPGP.js itself. These are often due to necessary changes that are of no interest to the upstream maintainers, mostly concerning build processes, eg. making node-only libraries available for frontend use. The `tweetnacl` fork is mainly there to shrink the dependency, since most of the library isn’t used.

There’s a [useful discussion](https://github.com/openpgpjs/openpgpjs/discussions/1574) on the topic that includes some analysis of the forks in regard to their upstreams, as well as explainations from the maintainers concerning the reasons for the forks and their versioning.

## Repo Dependency Chart

```mermaid
flowchart LR
    CORE -->|depends on| InternalLibraries
    CORE -->|depends on| PublicLibraries
    CORE -->|depends on| SoonObsolete
    CORE .->|will depend on| v6InternalLibraries
    CORE .->|no longer depends on| UnusedForks
    subgraph Core
      CORE(OpenPGP.js)
    end
    subgraph NoInternalDependencies [Repos with no internal dependencies]
      direction LR
      CLI(sop-openpgp.js)
      WEBSITE(openpgpjs.org website)
      GHA(Github Actions fork)
      HKP-CLIENT(HKP Client)
      WKD-CLIENT(WKD Client)
    end
    subgraph PublicLibraries [Public Libraries]
      direction LR
      WEB-STREAMS-POLYFILL(web-streams-polyfill fork)
      ARGON2ID(Argon2id)
    end
    subgraph InternalLibraries [Internal Libraries and Forks]
      direction LR
      ASMCRYPTO.JS(openpgp/asmcrypto.js fork)
      JSDOC(openpgp/jsdoc fork)
      PAKO(openpgp/pako fork)
      SEEK-BZIP(openpgp/seek-bzip fork)
      TWEETNACL(openpgp/tweetnacl fork)
      WEB-STREAM-TOOLS(openpgp/web-stream-tools) -->|depends on| JSDOC
    end
    subgraph v6InternalLibraries [Internal Libraries that will be added in v6]
      NOBLE-CURVES(Noble Curves fork)
      NOBLE-HASHES(Noble Hashes fork)
    end
    subgraph SoonObsolete [Internal Libraries that will be removed in v6]
      ELLIPTIC(openpgp/elliptic fork)
    end
    subgraph UnusedForks [Unused Forks]
      direction LR
      COMPRESSJS(compressjs fork, unused since 2018)
      ES6-PROMISE(es6-promise fork, seems unused?)
      EMAIL-ADDRESSES(email-addresses fork, replaced by upstream in 528fbfb, 2019)
    end
```
