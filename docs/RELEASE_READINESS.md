# Release readiness — crypto-lab-tool

Review date: 2 October 2026. Proposed work, not an implementation or release announcement.

## Appropriate next functionality

- Add authenticated encryption (for example AES-GCM), a versioned encrypted-file format and direct binary input/output.
- Add standard RSA key files and OAEP handling; retain raw RSA/CBC exercises as clearly labelled educational modes.
- Improve secret input, input-size limits, error reporting and safe output-overwrite behaviour. Do not introduce a home-grown cryptographic algorithm.

## Before a first public release

- Test tampered/truncated encrypted files, wrong keys, authentication failures and binary round trips using trusted vectors.
- Define key/nonce handling for the selected format and explain the limits of password-based encryption before offering it.
- Add an installable package/CLI, supported-version CI, consistent exit codes and clean installation examples. Keep the existing CI and build on it.
- Distinguish legacy MD5/SHA-1 checksum compatibility from security use. Avoid presenting textbook RSA or unauthenticated CBC as a production file-encryption solution.

## Shared release preparation

Before publishing a tagged release, choose a project licence after reviewing tutorial and asset provenance; document installation, supported versions, examples and known limits; add a changelog, issue/PR templates, contribution guidance and a vulnerability-reporting policy; run CI on the claimed platforms and test a clean installation. Add dependency updates and appropriate repository security checks where supported. Provide tagged release notes and usable download assets where relevant. These are readiness recommendations, not GitHub certification or features already delivered.

GitHub references: [community health files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file) and [releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
