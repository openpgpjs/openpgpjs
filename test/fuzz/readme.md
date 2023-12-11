# Fuzz Testing

Fuzz testing is

> An automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a program. 

This `fuzz/` directory contains the fuzz tests for openpgp.js.
To generate and run fuzz tests, we use the [Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js/) library.

## Running a fuzzer

This directory contains fuzz targets like for example `createMessageBinary`.

You can run this fuzz target without options:
```sh
npx jazzer test/fuzz/createMessageBinary.cjs
```
(You will notice the `.cjs` file ending. This is because jazzer does not support esm, yet)

or with the given settings at your package.json:

```sh
TARGET=createMessageBinary npm run fuzz
```
Notice, that `TARGET` is the name of your test file, the fuzz target module.

You should see the fuzzer that looks similar to this:

```
#128	pulse  corp: 1/1b lim: 4 exec/s: 64 rss: 173Mb
#256	pulse  corp: 1/1b lim: 6 exec/s: 51 rss: 173Mb
#512	pulse  corp: 1/1b lim: 8 exec/s: 46 rss: 174Mb
#1024	pulse  corp: 1/1b lim: 14 exec/s: 40 rss: 178Mb
#2048	pulse  corp: 1/1b lim: 21 exec/s: 40 rss: 179Mb
```

It will continue to generate random inputs forever, until it finds a bug or is terminated.
The testcases for bugs it finds can be seen in the form of `crash-*`, `timeout-*` or `oom-*` at `test/fuzz/reports`.

## Running with coverage
To generate a coverage report, run the `fuzz-coverage` script from the package.json:
```sh
TARGET=createMessageBinary npm run fuzz-coverage
```

The coverage reports can be found in `test/fuzz/coverage`.


## The fuzz target module
All functions that need to be fuzz-tested are here, at the `test/fuzz/` directory.

A fuzz target module needs to export a function called fuzz,
which takes a Buffer parameter and executes the actual code under test.

Jazzer.js provides the wrapper class FuzzedDataProvider, which allows reading primitive types from the Buffer.

See further details in [Fuzzing using fuzz targets and the CLI](https://github.com/CodeIntelligenceTesting/jazzer.js/blob/main/docs/fuzz-targets.md) or [Advanced Fuzzing Settings](https://github.com/CodeIntelligenceTesting/jazzer.js/blob/main/docs/fuzz-settings.md#advanced-fuzzing-settings)


### Run limitations

You can pass the `-max_total_time` flag to the internal fuzzing engine to stop the fuzzing run after 10 seconds.
```sh
npx jazzer test/fuzz/createMessageBinary.cjs -- -max_total_time=10
```

Or you can limit the number of runs:
```sh
npx jazzer test/fuzz/createMessageBinary.cjs -- -runs=4000000
```