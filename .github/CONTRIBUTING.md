# Contributing to the BeyondTrust Professional Services pre-check scripts

Thank you for your interest in contributing to our project!

Here is some information on how to get started and where to ask for help.

## Getting Started

The BeyondTrust Professional Services pre-check scripts are tools used by potential
and current customers to gather, validate, and report on readiness for BeyondTrust
PAM implementation projects. To ensure transparency with customers early in the project
and because these tools are not part of BeyondTrust product, they are provided in 
customer-viewable scripting languages.

## How can I Contribute?

### Reporting Bugs

Bugs should be submitted through BeyondTrust Support or through your project Implementation Manager. Any bugs should be submitted against the product for which your project is focused. Our support team will ensure the escalation is raised to the proper team internally.

If the bug is a security vulnerability, instead please refer to the [responsible disclosure section of our security policy](https://www.beyondtrust.com/security#disclosure).

### Feature Requests

Feature requests should also be submitted through your Implementation Manager. 

### Making Changes and Submitting a Pull Request

All tools in this repository are written to support the largest number of OSes and versions reasonable. This means all `.sh` scripts are Bourne Shell, not bash. Please review the [Bash man page](https://www.etalabs.net/sh_tricks.html), the [Bashism Wiki](https://mywiki.wooledge.org/Bashism) and [Rich's Sh Tricks](https://www.etalabs.net/sh_tricks.html) for references on handling bashisms that are illegal in POSIX `sh`.

#### **Did you write a patch that fixes a bug?**

- Open a GitHub pull request with the patch.
- Ensure the PR description clearly describes both the problem and the solution. If you have a support ticket, please include that number as well.
- We will review the changes and make a determination if we will accept the change or not.

#### **Do you intend to add a new feature or change an existing one?**

- Consider submitting a feature request through your Implementation Manager to ensure that your proposed changes do not conflict with new features that are already planned or in development.
- If you do open a PR, please ensure the description clearly describes what the change is, and what problem your change is solving.
- Any new code must include unit tests (if possible) or end-to-end tests. All tests must pass.
- We will review the change and determine if it fits within our goals for the project.

### Tests

Please note that all tests must pass for any change submitted to be accepted. This includes both the unit tests within the modules as well as the end-to-end tests.

#### Running End-to-End tests: Unix/Linux

These tools are designed to run on the following platforms:

- AIX:
  - 5, 6, 7, all TLs
- FreeBSD:
  - 8: i386
  - 9: i386, x86_64
- HP-UX:
  - 11.23: IA64 and PA-RISC
  - 11.31: IA64
- Linux: 
  - all i386/x86_64 kernels 2.4 and higher. initv, service, or systemd managed.
  - arm64 kernels 4 and higher
  - powerpc kernels 4 and higher
- Solaris: 
  - 8: SPARC and i386
  - 9: SPARC and i386
  - 10: SPARC, i386, X86_64
  - 11: SPARC, I386, X86_64

The tools are designed to run as root or non-root users and make no chances other than writing output to /tmp/

**We do not recommend running these tests on a production server.**

Run End-to-End tests by running `./pbis-pre-check.sh $activedirectorydomain`

#### Running End-to-End tests: Windows

The AD tools are designed to run on:
- Windows:
  - 2003 R2
  - 2008
  - 2008 R2
  - 2012
  - 2012 R2
  - 2016
  - 2019
  - 2022

Run end-to-end tests by running `cscript ad-info.vbs`

**We do not recommend running tests as a Domain Admin.**
