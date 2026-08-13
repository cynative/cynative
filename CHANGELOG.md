# Changelog

## [1.9.0](https://github.com/cynative/cynative/compare/v1.8.0...v1.9.0) (2026-08-13)


### Features

* named agents for the CLI ([#256](https://github.com/cynative/cynative/issues/256)) ([259d094](https://github.com/cynative/cynative/commit/259d09422adbeada21aa492b0e331c749a4a3495))


### Bug Fixes

* reserve the Host header so the wire authority cannot diverge from the URL ([#246](https://github.com/cynative/cynative/issues/246)) ([af26163](https://github.com/cynative/cynative/commit/af26163986eed2ef50030cc64e36e7260df0eb77)), closes [#243](https://github.com/cynative/cynative/issues/243)
* resolve GCP Container API reads ([#235](https://github.com/cynative/cynative/issues/235)) ([8751736](https://github.com/cynative/cynative/commit/8751736b1bab7845e93d20e292aaedfe40546ec3))


### Dependencies

* bump github.com/aws/aws-sdk-go-v2 from 1.43.0 to 1.43.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2 from 1.43.1 to 1.43.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2 from 1.43.2 to 1.43.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2 from 1.43.3 to 1.43.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream from 1.7.14 to 1.7.15 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream from 1.7.15 to 1.7.16 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/config from 1.32.31 to 1.32.32 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/config from 1.32.32 to 1.32.33 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/config from 1.32.33 to 1.32.34 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/config from 1.32.34 to 1.32.35 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/credentials from 1.19.30 to 1.19.31 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/credentials from 1.19.31 to 1.19.32 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/credentials from 1.19.32 to 1.19.33 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/credentials from 1.19.33 to 1.19.34 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/feature/ec2/imds from 1.18.31 to 1.18.32 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/feature/ec2/imds from 1.18.32 to 1.18.33 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/feature/ec2/imds from 1.18.33 to 1.18.34 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/feature/ec2/imds from 1.18.34 to 1.18.35 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/manager from 1.22.35 to 1.22.36 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/manager from 1.22.36 to 1.22.37 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/manager from 1.22.37 to 1.22.38 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/manager from 1.22.38 to 1.22.39 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/manager from 1.22.38 to 1.22.41 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager from 0.3.5 to 0.3.6 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager from 0.3.6 to 0.3.7 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager from 0.3.7 to 0.3.8 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager from 0.3.8 to 0.3.11 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager from 0.3.8 to 0.3.9 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump github.com/aws/aws-sdk-go-v2/internal/configsources from 1.4.31 to 1.4.32 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/internal/configsources from 1.4.32 to 1.4.33 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/internal/configsources from 1.4.33 to 1.4.34 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/internal/configsources from 1.4.34 to 1.4.35 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 from 2.7.31 to 2.7.32 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 from 2.7.32 to 2.7.33 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 from 2.7.33 to 2.7.34 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 from 2.7.34 to 2.7.35 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/internal/v4a from 1.4.32 to 1.4.33 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/internal/v4a from 1.4.33 to 1.4.34 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/internal/v4a from 1.4.34 to 1.4.35 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/internal/v4a from 1.4.35 to 1.4.36 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/ecr from 1.60.0 to 1.60.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/ecr from 1.60.1 to 1.60.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/ecr from 1.60.2 to 1.60.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/ecr from 1.60.3 to 1.60.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/ecrpublic from 1.41.0 to 1.41.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/ecrpublic from 1.41.1 to 1.41.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/ecrpublic from 1.41.2 to 1.41.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/ecrpublic from 1.41.3 to 1.41.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/eks from 1.90.0 to 1.90.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/eks from 1.90.1 to 1.90.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/eks from 1.90.2 to 1.90.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/eks from 1.90.3 to 1.90.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/iam from 1.56.0 to 1.56.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/iam from 1.56.1 to 1.56.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/iam from 1.56.2 to 1.57.0 ([fd56459](https://github.com/cynative/cynative/commit/fd564599c3d07b454cd78abbfe3bc0930ba3252c))
* bump github.com/aws/aws-sdk-go-v2/service/iam from 1.57.0 to 1.57.1 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/iam from 1.57.1 to 1.58.1 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding from 1.13.13 to 1.13.14 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding from 1.13.14 to 1.13.15 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/internal/checksum from 1.9.24 to 1.9.25 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/internal/checksum from 1.9.25 to 1.9.26 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/internal/checksum from 1.9.26 to 1.9.27 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/internal/checksum from 1.9.27 to 1.9.28 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/internal/presigned-url from 1.13.31 to 1.13.32 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/internal/presigned-url from 1.13.32 to 1.13.33 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/internal/presigned-url from 1.13.33 to 1.13.34 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/internal/presigned-url from 1.13.34 to 1.13.35 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/internal/s3shared from 1.19.32 to 1.19.33 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/internal/s3shared from 1.19.33 to 1.19.34 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/internal/s3shared from 1.19.34 to 1.19.35 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/internal/s3shared from 1.19.35 to 1.19.36 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/kms from 1.55.0 to 1.55.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/kms from 1.55.1 to 1.55.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/kms from 1.55.2 to 1.55.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/kms from 1.55.3 to 1.55.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.106.0 to 1.106.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.106.1 to 1.106.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.106.2 to 1.106.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.106.3 to 1.106.4 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.106.3 to 1.107.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/signin from 1.5.0 to 1.5.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/signin from 1.5.1 to 1.5.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/signin from 1.5.2 to 1.5.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/signin from 1.5.3 to 1.5.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/sso from 1.33.0 to 1.33.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/sso from 1.33.1 to 1.33.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/sso from 1.33.2 to 1.33.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/sso from 1.33.3 to 1.33.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/ssooidc from 1.38.0 to 1.38.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/ssooidc from 1.38.1 to 1.38.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/ssooidc from 1.38.2 to 1.38.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/ssooidc from 1.38.3 to 1.38.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/aws-sdk-go-v2/service/sts from 1.45.0 to 1.45.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/aws/aws-sdk-go-v2/service/sts from 1.45.1 to 1.45.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/aws/aws-sdk-go-v2/service/sts from 1.45.2 to 1.45.3 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/aws/aws-sdk-go-v2/service/sts from 1.45.3 to 1.45.4 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/aws/smithy-go from 1.27.5 to 1.27.6 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/buger/jsonparser from 1.5.0 to 1.6.0 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/buger/jsonparser from 1.6.0 to 1.6.1 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/bytedance/sonic/loader from 0.5.1 to 0.5.2 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/cloudflare/circl from 1.6.4 to 1.6.5 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/docker/cli from 29.6.2+incompatible to 29.7.0+incompatible ([fd56459](https://github.com/cynative/cynative/commit/fd564599c3d07b454cd78abbfe3bc0930ba3252c))
* bump github.com/docker/cli from 29.7.0+incompatible to 29.7.1+incompatible ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/docker/cli from 29.7.1+incompatible to 29.7.2+incompatible ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/go-git/go-git/v5 from 5.19.1 to 5.19.2 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/google/go-containerregistry from 0.21.7 to 0.21.8 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/google/go-containerregistry from 0.21.8 to 0.21.9 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/googleapis/enterprise-certificate-proxy from 0.3.19 to 0.3.20 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/googleapis/enterprise-certificate-proxy from 0.3.19 to 0.3.20 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.29.0 to 2.30.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/ipfs/boxo from 0.42.0 to 0.42.1 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/jgautheron/goconst from 1.10.2 to 1.11.0 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump github.com/klauspost/compress from 1.19.1 to 1.19.2 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/lucasb-eyer/go-colorful from 1.4.0 to 1.4.1 ([504b3cb](https://github.com/cynative/cynative/commit/504b3cb2676f539c45a1662623401a040733a590))
* bump github.com/maximhq/bifrost/core from 1.7.4 to 1.7.5 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github.com/maximhq/bifrost/core from 1.7.5 to 1.7.6 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/modelcontextprotocol/registry from 1.8.0 to 1.8.1 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/rogpeppe/go-internal from 1.15.0 to 1.16.0 ([504b3cb](https://github.com/cynative/cynative/commit/504b3cb2676f539c45a1662623401a040733a590))
* bump github.com/santhosh-tekuri/jsonschema/v6 from 6.0.2 to 6.0.3 ([770941c](https://github.com/cynative/cynative/commit/770941c5b2533118f211a66fb94558a291465ceb))
* bump github.com/sigstore/cosign/v3 from 3.1.2 to 3.1.3 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump github.com/sigstore/sigstore from 1.10.8 to 1.10.9 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump github.com/sigstore/sigstore-go from 1.2.2 to 1.3.0 ([fd56459](https://github.com/cynative/cynative/commit/fd564599c3d07b454cd78abbfe3bc0930ba3252c))
* bump github/codeql-action/analyze from 4.37.3 to 4.37.4 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github/codeql-action/analyze from 4.37.4 to 4.37.5 ([770941c](https://github.com/cynative/cynative/commit/770941c5b2533118f211a66fb94558a291465ceb))
* bump github/codeql-action/analyze from 4.37.5 to 4.37.6 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump github/codeql-action/init from 4.37.3 to 4.37.4 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))
* bump github/codeql-action/init from 4.37.4 to 4.37.5 ([770941c](https://github.com/cynative/cynative/commit/770941c5b2533118f211a66fb94558a291465ceb))
* bump github/codeql-action/init from 4.37.5 to 4.37.6 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump go.opentelemetry.io/contrib/detectors/gcp from 1.44.0 to 1.45.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc from 0.69.0 to 0.70.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp from 0.69.0 to 0.70.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/otel from 1.44.0 to 1.45.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/otel from 1.44.0 to 1.45.0 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump go.opentelemetry.io/otel/metric from 1.44.0 to 1.45.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/otel/metric from 1.44.0 to 1.45.0 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump go.opentelemetry.io/otel/sdk from 1.44.0 to 1.45.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/otel/sdk from 1.44.0 to 1.45.0 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump go.opentelemetry.io/otel/sdk/metric from 1.44.0 to 1.45.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/otel/sdk/metric from 1.44.0 to 1.45.0 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump go.opentelemetry.io/otel/trace from 1.44.0 to 1.45.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump go.opentelemetry.io/otel/trace from 1.44.0 to 1.45.0 ([77822c1](https://github.com/cynative/cynative/commit/77822c15a1d545385b616385ccb26b270a297979))
* bump golang.org/x/arch from 0.29.0 to 0.30.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump google.golang.org/api from 0.290.0 to 0.291.0 ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump google.golang.org/api from 0.291.0 to 0.292.0 ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump google.golang.org/genproto/googleapis/api from 0.0.0-20260630182238-925bb5da69e7 to 0.0.0-20260727163830-6c54dddc4772 ([792ce75](https://github.com/cynative/cynative/commit/792ce75b5b9351d4c754dd71f1442bd678c63149))
* bump google.golang.org/genproto/googleapis/api from 0.0.0-20260727163830-6c54dddc4772 to 0.0.0-20260803160001-6ac0973c030d ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump google.golang.org/genproto/googleapis/rpc from 0.0.0-20260706201446-f0a921348800 to 0.0.0-20260724162435-b2f20204f0df ([e40b886](https://github.com/cynative/cynative/commit/e40b886dccec1376eceaaf56e74a193f8280e95c))
* bump google.golang.org/genproto/googleapis/rpc from 0.0.0-20260724162435-b2f20204f0df to 0.0.0-20260803160001-6ac0973c030d ([cf41a76](https://github.com/cynative/cynative/commit/cf41a7611313d7efa9ffeaa2ecdcdb8fa7eb9085))
* bump google.golang.org/grpc from 1.82.1 to 1.83.0 ([93b737b](https://github.com/cynative/cynative/commit/93b737b94c5e2e09063843b824e7c78ada9094c6))

## [1.8.0](https://github.com/cynative/cynative/compare/v1.7.0...v1.8.0) (2026-07-28)


### Features

* add optional --live-llm probe to cynative doctor ([#210](https://github.com/cynative/cynative/issues/210)) ([7b9d055](https://github.com/cynative/cynative/commit/7b9d055d350eb75e4e4ebb2e3c50509ea4acff9a))
* publish a cosign signature alongside the release archives ([#224](https://github.com/cynative/cynative/issues/224)) ([ff43b4a](https://github.com/cynative/cynative/commit/ff43b4a6ecf36c51e168274fa39838e5b5c44b2b))


### Dependencies

* bump github.com/aws/smithy-go from 1.27.4 to 1.27.5 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/AzureAD/microsoft-authentication-library-for-go from 1.7.2 to 1.8.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/buger/jsonparser from 1.2.0 to 1.5.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/docker/go-connections from 0.7.0 to 0.8.0 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))
* bump github.com/docker/go-connections from 0.8.0 to 0.8.1 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/runtime from 0.32.6 to 0.33.0 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))
* bump github.com/go-openapi/runtime/server-middleware from 0.32.6 to 0.33.0 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))
* bump github.com/go-openapi/swag from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/cmdutils from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/conv from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/fileutils from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/jsonutils from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/loading from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/mangling from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/netutils from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/pools from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/stringutils from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/typeutils from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/go-openapi/swag/yamlutils from 0.27.3 to 0.28.0 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/goreleaser/goreleaser/v2 from 2.17.0 to 2.17.1 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))
* bump github.com/maximhq/bifrost/core from 1.7.3 to 1.7.4 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))
* bump github.com/moby/moby/client from 0.5.0 to 0.5.1 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump github.com/valyala/fasthttp from 1.72.0 to 1.73.0 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))
* bump github.com/yuin/goldmark from 1.8.4 to 1.8.5 ([9af52d1](https://github.com/cynative/cynative/commit/9af52d1597f144f549e4c3c9a860c39d73d3f58c))
* bump go.yaml.in/yaml/v3 from 3.0.4 to 3.0.5 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))
* bump mvdan.cc/gofumpt from 0.10.0 to 0.11.0 ([b304e27](https://github.com/cynative/cynative/commit/b304e27c89d247fe7ada6eaa614e9312b704d625))

## [1.7.0](https://github.com/cynative/cynative/compare/v1.6.0...v1.7.0) (2026-07-24)


### Features

* add cynative doctor for config and connector readiness ([#169](https://github.com/cynative/cynative/issues/169)) ([b7ca3e8](https://github.com/cynative/cynative/commit/b7ca3e8e78acf36f2b92ef9baf742ef7023c43ae))


### Bug Fixes

* **ci:** keep Dependabot changelog overrides under a huge PR body ([#186](https://github.com/cynative/cynative/issues/186)) ([2445c12](https://github.com/cynative/cynative/commit/2445c1263f60f7e529a09797e0bdf2c253551d3a))


### Dependencies

* bump 4 more dependencies ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump aws-actions/configure-aws-credentials from 6.2.2 to 6.2.3 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* bump cloud.google.com/go/kms from 1.32.0 to 1.33.0 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump cloud.google.com/go/storage from 1.63.1 to 1.64.0 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9 from 9.3.0 to 9.4.0 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* bump github.com/gabriel-vasile/mimetype from 1.4.14 to 1.4.15 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* bump github.com/go-git/go-billy/v5 from 5.9.0 to 5.9.1 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/go-logr/logr from 1.4.3 to 1.4.4 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/analysis from 0.25.3 to 0.25.5 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/loads from 0.24.0 to 0.25.0 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/runtime from 0.32.5 to 0.32.6 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/runtime/server-middleware from 0.32.5 to 0.32.6 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/spec from 0.22.6 to 0.22.9 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/cmdutils from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/conv from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/fileutils from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/jsonutils from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/loading from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/mangling from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/netutils from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/pools from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/stringutils from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/go-openapi/swag/typeutils from 0.27.2 to 0.27.3 ([e2a6192](https://github.com/cynative/cynative/commit/e2a619205bfd854ca61b203193a64d68ee2941af))
* bump github.com/googleapis/enterprise-certificate-proxy from 0.3.18 to 0.3.19 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp from 1.34.0 to 1.35.0 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric from 0.58.0 to 0.59.0 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping from 0.58.0 to 0.59.0 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/leodido/go-urn from 1.4.0 to 1.5.0 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* bump github.com/mark3labs/mcp-go from 0.56.0 to 0.57.0 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* bump github.com/mattn/go-isatty from 0.0.23 to 0.0.24 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/mattn/go-runewidth from 0.0.24 to 0.0.27 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/oklog/ulid/v2 from 2.1.1 to 2.1.2 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump github.com/prometheus/client_golang from 1.24.0 to 1.24.1 ([298539e](https://github.com/cynative/cynative/commit/298539e2c1e530f5f9de9de06e0c0b69caab0d6c))
* bump google.golang.org/api from 0.289.0 to 0.290.0 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* bump k8s.io/apimachinery from 0.36.2 to 0.36.3 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* bump k8s.io/client-go from 0.36.2 to 0.36.3 ([28169c8](https://github.com/cynative/cynative/commit/28169c843d45d929419877bd706d13bf0647730e))
* Bump the "all-dependencies" group with 1 update across multiple ecosystems ([#177](https://github.com/cynative/cynative/issues/177)) ([b851846](https://github.com/cynative/cynative/commit/b851846256d45edf57e191dd6abd4d51456a2391))

## [1.6.0](https://github.com/cynative/cynative/compare/v1.5.5...v1.6.0) (2026-07-20)


### Features

* add shell completions for bash, zsh, fish, and powershell ([#167](https://github.com/cynative/cynative/issues/167)) ([101ecab](https://github.com/cynative/cynative/commit/101ecabf3e5701e5820ffaf804ad1bcaa9861b30))


### Dependencies

* bump the all-dependencies group with 19 updates ([#164](https://github.com/cynative/cynative/issues/164)) ([fb335e7](https://github.com/cynative/cynative/commit/fb335e7544b81f78c42dbf213b428a7e857ebaf7))

## [1.5.5](https://github.com/cynative/cynative/compare/v1.5.4...v1.5.5) (2026-07-18)


### Dependencies

* bump github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager from 0.3.2 to 0.3.3 ([17b9365](https://github.com/cynative/cynative/commit/17b9365731500edcaac9f4dd93ae4e594e2578ab))
* bump github.com/aws/smithy-go from 1.27.3 to 1.27.4 ([17b9365](https://github.com/cynative/cynative/commit/17b9365731500edcaac9f4dd93ae4e594e2578ab))
* bump github.com/dlclark/regexp2/v2 from 2.5.0 to 2.5.1 ([17b9365](https://github.com/cynative/cynative/commit/17b9365731500edcaac9f4dd93ae4e594e2578ab))

## [1.5.4](https://github.com/cynative/cynative/compare/v1.5.3...v1.5.4) (2026-07-17)


### Bug Fixes

* decode byte[] checksum body in the Windows installer ([#148](https://github.com/cynative/cynative/issues/148)) ([d824d54](https://github.com/cynative/cynative/commit/d824d54b822326178de81926af2849b4b1754af7))

## [1.5.3](https://github.com/cynative/cynative/compare/v1.5.2...v1.5.3) (2026-07-16)


### Bug Fixes

* **deps:** Bump the all-dependencies group with 4 updates ([#142](https://github.com/cynative/cynative/issues/142)) ([4058867](https://github.com/cynative/cynative/commit/40588670648336fcf4f51f8bd16dbb4aa1985ab5))


### Dependencies

* bump github.com/aws/aws-sdk-go-v2/feature/s3/manager from 1.22.33 to 1.22.34 ([ae5f712](https://github.com/cynative/cynative/commit/ae5f71290e8fb35743282d28ad35d03b7402b5c5))
* bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.105.1 to 1.105.2 ([ae5f712](https://github.com/cynative/cynative/commit/ae5f71290e8fb35743282d28ad35d03b7402b5c5))
* bump github.com/docker/cli from 29.6.1+incompatible to 29.6.2+incompatible ([ae5f712](https://github.com/cynative/cynative/commit/ae5f71290e8fb35743282d28ad35d03b7402b5c5))
* bump google.golang.org/api from 0.288.0 to 0.289.0 ([ae5f712](https://github.com/cynative/cynative/commit/ae5f71290e8fb35743282d28ad35d03b7402b5c5))

## [1.5.2](https://github.com/cynative/cynative/compare/v1.5.1...v1.5.2) (2026-07-16)


### Bug Fixes

* bound the GCP token refresh with a client-side HTTP timeout ([#136](https://github.com/cynative/cynative/issues/136)) ([3f66e87](https://github.com/cynative/cynative/commit/3f66e87af80d437a4dc37284aaef8d8503d0b467)), closes [#131](https://github.com/cynative/cynative/issues/131)
* bound the Kubernetes ClusterRole preflight against a stalled cluster ([#130](https://github.com/cynative/cynative/issues/130)) ([fc16c28](https://github.com/cynative/cynative/commit/fc16c287d2c0db3389ac5e813b26ed6742c7d56e))
* **deps:** Bump the "all-dependencies" group with 1 update across multiple ecosystems ([#124](https://github.com/cynative/cynative/issues/124)) ([15aa538](https://github.com/cynative/cynative/commit/15aa5383bd6462f1e0e756d7252555a5c23d9c58))
* **deps:** Bump the all-dependencies group with 2 updates ([#135](https://github.com/cynative/cynative/issues/135)) ([2134362](https://github.com/cynative/cynative/commit/213436276e742526cfba05b67d50936bf7388773))
* **deps:** Bump the all-dependencies group with 23 updates ([#128](https://github.com/cynative/cynative/issues/128)) ([6db1011](https://github.com/cynative/cynative/commit/6db101106eb71ffb0a2fb597f36a588b1cbd1602))
* **deps:** Bump the all-dependencies group with 4 updates ([#110](https://github.com/cynative/cynative/issues/110)) ([7d733a9](https://github.com/cynative/cynative/commit/7d733a924d22692da9203fb8533d5675b2437b8f))
* **deps:** pin go-msix to v0.3.1 to keep the release snapshot building ([#132](https://github.com/cynative/cynative/issues/132)) ([b0814fa](https://github.com/cynative/cynative/commit/b0814fa042b1ef8b561ce286084c9a18b757998b))

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
