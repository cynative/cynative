# Changelog

## [1.5.1](https://github.com/cynative/cynative/compare/v1.5.0...v1.5.1) (2026-07-10)


### Bug Fixes

* **deps:** Bump google.golang.org/api in the all-dependencies group ([#100](https://github.com/cynative/cynative/issues/100)) ([f34359f](https://github.com/cynative/cynative/commit/f34359fca72acf30ba32db954642e50af7f44113))
* **deps:** Bump the "all-dependencies" group with 1 update across multiple ecosystems ([#92](https://github.com/cynative/cynative/issues/92)) ([510e50b](https://github.com/cynative/cynative/commit/510e50b18969acc3238aaa6d1568490d6f5c5490))
* **deps:** Bump the "all-dependencies" group with 1 update across multiple ecosystems ([#94](https://github.com/cynative/cynative/issues/94)) ([e071b4d](https://github.com/cynative/cynative/commit/e071b4d9c0f4fb72007d4123a8543dc558f0e70a))
* **deps:** Bump the all-dependencies group with 3 updates ([#93](https://github.com/cynative/cynative/issues/93)) ([0b6cb88](https://github.com/cynative/cynative/commit/0b6cb88fc2dcd2acdfb7387b3d3c5070561a1c99))
* retry transient LLM provider errors by default ([#99](https://github.com/cynative/cynative/issues/99)) ([d076cd6](https://github.com/cynative/cynative/commit/d076cd6eaacaf018dc149a10041f014e26fe9368))

## [1.5.0](https://github.com/cynative/cynative/compare/v1.4.1...v1.5.0) (2026-07-05)


### Features

* **install:** add CYNATIVE_BASE_URL test seam to install.sh ([#61](https://github.com/cynative/cynative/issues/61)) ([097f0fe](https://github.com/cynative/cynative/commit/097f0fe5038ac593dd5d62a8ef3bc605fe827227))


### Bug Fixes

* **deps:** Bump charm.land/lipgloss/v2 in the all-dependencies group ([#86](https://github.com/cynative/cynative/issues/86)) ([e3003b7](https://github.com/cynative/cynative/commit/e3003b7bddfc6a75fabd9b1c6170bed8378c8361))
* **deps:** bump sigstore/timestamp-authority to v2.1.2 ([#89](https://github.com/cynative/cynative/issues/89)) ([4ddf556](https://github.com/cynative/cynative/commit/4ddf556c87b61abecbdd8d7ed42777d82f8a1249))
* **deps:** Bump the all-dependencies group with 3 updates ([#37](https://github.com/cynative/cynative/issues/37)) ([2665f14](https://github.com/cynative/cynative/commit/2665f14ca21d455e6180c81a819db607a3941f60))
* **deps:** Bump the all-dependencies group with 5 updates ([#79](https://github.com/cynative/cynative/issues/79)) ([18883c5](https://github.com/cynative/cynative/commit/18883c5090937d7e969a0c865d76b720e75e1efe))

## [1.4.1](https://github.com/cynative/cynative/compare/v1.4.0...v1.4.1) (2026-07-01)


### Bug Fixes

* **gcp:** keep all Discovery API versions in the action-gate catalog ([#32](https://github.com/cynative/cynative/issues/32)) ([c3a8c4f](https://github.com/cynative/cynative/commit/c3a8c4fb2f53fe76e00cd4fa443bbcff7fed6055))
* use bare :monterey symbol in Homebrew depends_on macos ([#30](https://github.com/cynative/cynative/issues/30)) ([e016735](https://github.com/cynative/cynative/commit/e016735b4d06f6cd182c181c0f64230ac9f97efd))

## [1.4.0](https://github.com/cynative/cynative/compare/v1.3.0...v1.4.0) (2026-06-30)


### Features

* split macOS distribution — Homebrew Formula + direct-download pkg ([#28](https://github.com/cynative/cynative/issues/28)) ([052f445](https://github.com/cynative/cynative/commit/052f44573b0621a304a18ebae71bfa3de2c59ba8))

## [1.3.0](https://github.com/cynative/cynative/compare/v1.2.1...v1.3.0) (2026-06-30)


### Features

* ship signed, notarized, stapled macOS .pkg installers from Linux CI ([#24](https://github.com/cynative/cynative/issues/24)) ([9149528](https://github.com/cynative/cynative/commit/91495286abf1e8b68f8415cc6310fddc54d124d3))


### Bug Fixes

* **deps:** bump github.com/sigstore/rekor to v1.5.2 (CVE-2026-48702) ([#22](https://github.com/cynative/cynative/issues/22)) ([3db8f69](https://github.com/cynative/cynative/commit/3db8f6974677824db80cf4d0264a38bcc9997404))
* **deps:** Bump the all-dependencies group with 5 updates ([#25](https://github.com/cynative/cynative/issues/25)) ([db454e4](https://github.com/cynative/cynative/commit/db454e4382ed4757449c057ec6b9955e518ea13f))

## [1.2.1](https://github.com/cynative/cynative/compare/v1.2.0...v1.2.1) (2026-06-29)


### Bug Fixes

* **deps:** Bump github.com/aws/smithy-go in the all-dependencies group ([#20](https://github.com/cynative/cynative/issues/20)) ([b06d1c9](https://github.com/cynative/cynative/commit/b06d1c966440a5f3567cbf75f3e4eeb0d69eba2d))

## [1.2.0](https://github.com/cynative/cynative/compare/v1.1.0...v1.2.0) (2026-06-26)


### Features

* self-evident connector status lines + startup ceiling validation ([#15](https://github.com/cynative/cynative/issues/15)) ([0048bc7](https://github.com/cynative/cynative/commit/0048bc72df6a007fad23bea59fbcf1b60e401327))

## [1.1.0](https://github.com/cynative/cynative/compare/v1.0.0...v1.1.0) (2026-06-25)


### Features

* add cynative --version flag ([#6](https://github.com/cynative/cynative/issues/6)) ([c282718](https://github.com/cynative/cynative/commit/c28271855f9ec82fb1378445d414af575c969b34))
* add Windows installation support (install.ps1 + Scoop) ([#9](https://github.com/cynative/cynative/issues/9)) ([0f8e3e5](https://github.com/cynative/cynative/commit/0f8e3e5a8f3d300ef26e537c9687e3240d2f0e9e))

## 1.0.0 (2026-06-24)


### Features

* initial public release of cynative ([f5c3ce1](https://github.com/cynative/cynative/commit/f5c3ce1f04886edc2425198bc106b848e1132c51))

## Changelog
