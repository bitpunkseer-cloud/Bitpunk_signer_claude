# Bitpunk Signer

QWERTY 키보드와 카메라를 갖춘 휴대용 기기를 위한 **100% 에어갭 Bitcoin 전용 서명 장치** 펌웨어.

- Rust 기반, `embit`·`libwally-core` 등에 의존하지 않는 독자 구현
- 무선(Wi-Fi/BT)·NFC·USB 데이터 없음. 데이터 출력은 **화면 QR**과 **microSD**뿐
- 펌웨어 설치/업데이트는 microSD로만
- 기본은 아무것도 저장하지 않음. 원하면 **PIN으로 잠근 보관함**(SE050 보안 칩, 10회 틀리면 암호 소거, 속임수 PIN, 탬퍼 점검)에 시드·지갑·설정을 보관

## 시뮬레이터
기기 화면과 같은 코드로 그려지는 웹 시뮬레이터입니다.
- GitHub Pages: https://bitpunkseer-cloud.github.io/Bitpunk_signer_claude/ (기본 브랜치 푸시마다 자동 배포)
- 페이지 아래 **기능 점검표**(영·한)로 기기의 모든 기능을 어디서 찾는지 보고 직접 확인할 수 있습니다. 화면에서 `?`를 누르면 그 화면의 도움말이 열립니다.

로컬 빌드:
```sh
rustup target add wasm32-unknown-unknown
./sim/build.sh            # dist/site/index.html 생성
```

## 개발
```sh
cargo test --all
cargo clippy --all-targets -- -D warnings
rustup target add thumbv7em-none-eabihf
cargo build --target thumbv7em-none-eabihf -p bp-app   # no_std 확인
```

## 문서
- 아키텍처: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 로드맵: [docs/ROADMAP.md](docs/ROADMAP.md)
- UX 언어 (화면 규범): [docs/UX_LANGUAGE.md](docs/UX_LANGUAGE.md)
- 기능 대장: [docs/FEATURE_INVENTORY.md](docs/FEATURE_INVENTORY.md)
- 보안 저장(M10): [docs/milestones/M10_PLAN.md](docs/milestones/M10_PLAN.md), SE050 드라이버: [docs/M10_SE050.md](docs/M10_SE050.md)
- 하드웨어/운영 요구사항: [docs/HARDWARE_REQUIREMENTS.md](docs/HARDWARE_REQUIREMENTS.md)
- 레퍼런스 기능 전수조사: [docs/FEATURE_SURVEY.md](docs/FEATURE_SURVEY.md)
- 레퍼런스 프로젝트: [docs/REFERENCES.md](docs/REFERENCES.md)

## 라이선스
코드: MIT. 내장 비트맵 폰트는 JetBrains Mono(SIL OFL 1.1)에서 생성했습니다 — `crates/bp-ui/fonts/` 참조.
시험에서만 쓰는 참조 크레이트(예: SE050 바이트 비교용 `se05x`, LGPL-3.0)는 `dev-dependencies`로만 들어가며 펌웨어에는 포함되지 않습니다.
