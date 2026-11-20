# Bitpunk Signer 아키텍처

## 1. 설계 원칙

1. **하나의 코드, 두 개의 실행 환경.** 앱 로직과 화면 그리기는 실제 기기와 웹 시뮬레이터가 **같은 Rust 코드**를 씁니다.
   차이는 하드웨어 경계(HAL) 구현뿐입니다. 시뮬레이터에서 본 화면이 곧 기기 화면입니다.
2. **`no_std` 우선.** 암호·비트코인·QR·UI·앱 크레이트는 운영체제 없이 동작하도록 `#![no_std]` (+ 필요 시 `alloc`)로 작성합니다.
   CI가 ARM Cortex-M 타깃(`thumbv7em-none-eabihf`)으로 빌드해 이를 강제합니다.
3. **독자 구현 + 대조 검증.** 제품 코드는 외부 비트코인/암호 라이브러리에 의존하지 않습니다.
   `rust-bitcoin`, `libsecp256k1` 등은 **`dev-dependencies`(테스트 전용)** 로만 사용해 결과를 대조합니다.
4. **비밀값 수명 최소화.** 시드·개인키는 전용 타입에 담고 `Drop` 시 메모리를 0으로 덮습니다(volatile write).
   `Debug`/`Display` 구현으로 비밀값이 출력되지 않게 합니다.
5. **상수 시간.** 비밀값에 의존하는 분기·메모리 접근을 금지합니다(Phase 1A에서 검증 도구 도입).
6. **출력 경로는 화면과 SD뿐.** HAL에 무선·USB·NFC 인터페이스를 **정의하지 않습니다**. 코드 레벨에서도 통신 경로가 존재하지 않습니다.

## 2. 크레이트 구조

```
crates/
├─ bp-crypto    #![no_std]  해시, HMAC, PBKDF2, secp256k1, ECDSA, Schnorr, 비밀값 타입   (Phase 1A)
├─ bp-bitcoin   #![no_std]  BIP-39/32, 주소, 스크립트, PSBT, 디스크립터               (Phase 1B~)
├─ bp-qr        #![no_std]  QR 인코드/디코드, SeedQR, BC-UR, BBQr                     (Phase 1C~)
├─ bp-hal       #![no_std]  하드웨어 경계: 화면, 키 입력, 카메라, SD, 난수, 시계 (trait 정의만)
├─ bp-ui        #![no_std]  그리기 기본 요소, 비트맵 폰트, 위젯, 테마
├─ bp-app       #![no_std]  화면 상태 머신(메뉴/흐름), 설정, 기능 연결
└─ bp-sim-web   std, wasm   시뮬레이터용 HAL 구현 + JS로 내보내는 함수
sim/web/                    시뮬레이터 페이지(기기 외형, QWERTY 키보드, 캔버스)
tools/                      폰트 생성 등 개발 도구
```

의존 방향 (위 → 아래로만 의존):

```
        bp-sim-web (웹)        bp-fw-<board> (Phase 4, 실제 기기)
                 \               /
                      bp-app
              /     |      |      \
          bp-ui  bp-qr  bp-bitcoin  bp-hal
            |              |
          bp-hal       bp-crypto
```

## 3. HAL (하드웨어 경계)

| trait | 역할 | 시뮬레이터 구현 | 기기 구현 (Phase 4) |
|---|---|---|---|
| `Canvas` | 픽셀 채우기, 알파 블렌딩 | RGBA 프레임버퍼 → HTML canvas | LCD 드라이버 |
| `KeyEvent` (타입) | QWERTY 키 + 수정키(Shift/Ctrl/Alt/Fn) | PC 키보드 / 화면 키 클릭 | 키보드 매트릭스 스캔 |
| `Camera` | 흑백 프레임 공급 | 이미지 업로드 / QR 텍스트 붙여넣기 | 카메라 센서 |
| `Storage` | SD 파일 읽기/쓰기 | 브라우저 메모리 | FAT on microSD |
| `Rng` | 하드웨어 난수 | `crypto.getRandomValues` | TRNG 주변장치 |

- 화면 기준 해상도: **800×480 (5:3 가로형)** — 참고 기기들의 5~7" 가로형 패널에 맞춘 값. Phase 4 보드 선정 시 확정.
- 키보드 배열: M5Stack CardKB v1.1 실물 배열 50키 (HARDWARE_REQUIREMENTS.md 1.1). 방향키 4개, Esc, Enter, Del, Tab, Shift, Sym, Fn. QR 스캐너는 Fn+Q.

## 4. UI / 키보드 UX 규칙

| 키 | 동작 |
|---|---|
| ▲ ▼ | 목록 이동 |
| ◄ ► | 값 변경, 페이지 이동 |
| Enter | 선택/확인 |
| Esc / Del(빈 입력일 때) | 뒤로 |
| Fn+Q | 메뉴 어디서든 스캐너 열기 |
| 1~9 | 메뉴 항목 바로 선택 |
| 문자 키 | 텍스트 입력 (니모닉, 패스프레이즈 등) |

- 상단 상태바: 화면 제목 · 네트워크 배지(MAIN/TEST/SIGNET/REGTEST) · `AIR-GAPPED` 표시
- 하단 도움말바: 현재 화면에서 쓸 수 있는 키 안내
- 테마: 검은 배경 + 비트코인 오렌지 강조색, 큰 글씨 위주
- 폰트: JetBrains Mono(SIL OFL 1.1)를 4비트 비트맵으로 미리 변환해 펌웨어에 포함(`tools/gen_font.py`).
  한글 폰트는 다국어 작업 시 추가합니다.

## 5. 시뮬레이터 동작 방식

```
[브라우저]
  index.html ── 기기 외형(CSS) + QWERTY 키(버튼) + <canvas 800×480>
      │ 키 입력 → bp_key(code, ch, mods)
      │ 매 프레임 → bp_tick(ms) → 화면이 바뀌었으면 프레임버퍼를 canvas에 복사
      ▼
  bp_sim_web.wasm (Rust) ── bp-app ── bp-ui ── 같은 코드가 기기에서도 동작
```

- `wasm-bindgen` 같은 도구 없이 C ABI 함수 몇 개만 내보내 의존성을 최소화합니다.
- 빌드 스크립트(`sim/build.sh`)가 WASM을 HTML 안에 base64로 넣어 **파일 하나짜리 시뮬레이터**를 만듭니다.
- 배포: (1) Claude 아티팩트 링크 — Claude Code/Claude 앱에서 바로 열기, (2) GitHub Pages — 일반 브라우저용.

## 6. 버전 & 빌드 정보

- 시뮬레이터와 펌웨어 화면의 About 메뉴에 버전과 git 커밋 해시를 표시해, 지금 보는 화면이 어느 빌드인지 확인할 수 있게 합니다.

## 7. 테스트 전략

| 수준 | 내용 |
|---|---|
| 단위 테스트 | 각 크레이트 `cargo test` |
| 공식 테스트 벡터 | BIP-32/39/173/340/341/350 등, Wycheproof |
| 대조 테스트 | `dev-dependencies`의 rust-bitcoin / libsecp256k1과 무작위 입력 결과 비교 |
| 퍼징 | 파서(PSBT, QR, UR, 디스크립터) 대상 |
| no_std 빌드 | `thumbv7em-none-eabihf` 타깃 빌드로 표준 라이브러리 사용 차단 |
| UI 스냅샷 | 앱 상태별 프레임버퍼를 PNG로 렌더링해 변경 확인 |
