# Bitpunk Signer 로드맵

- 범위: **Bitcoin 전용** · 100% 에어갭 (무선/NFC/USB 데이터 없음) · 카메라 QR + microSD · QWERTY 키보드
- 언어: Rust, `embit`/`libwally` 등에 의존하지 않는 독자 구현
- 근거 문서: [FEATURE_SURVEY.md](FEATURE_SURVEY.md), [HARDWARE_REQUIREMENTS.md](HARDWARE_REQUIREMENTS.md)
- 진행 규칙: 각 단계(그리고 단계 안의 큰 작업)는 **구현 방향 제시 → 승인 → 구현 → 커밋/푸시 → 시뮬레이터 링크 제공** 순서로 진행합니다.

---

## Phase 0 — 기반 구축

목표: 코드를 쌓을 토대와, 매 빌드를 확인할 시뮬레이터 파이프라인.

| 항목 | 내용 |
|---|---|
| 0.1 아키텍처 설계 문서 | 크레이트 구조, HAL(하드웨어 추상화) 경계, 메모리/비밀값 처리 원칙(zeroize, no_std 지향) |
| 0.2 Rust 워크스페이스 | `bp-crypto`, `bp-bitcoin`, `bp-qr`, `bp-ui`, `bp-hal`, `bp-app`, `bp-sim-web` 골격 |
| 0.3 CI | `cargo test`, `clippy`, `fmt`, 테스트 벡터 실행 (GitHub Actions) |
| 0.4 웹 시뮬레이터 셸 | WASM 빌드, 참고 이미지와 같은 가로형 화면 + QWERTY 키보드 렌더링, PC 키보드/터치 입력 매핑 |
| 0.5 자동 배포 | 푸시할 때마다 GitHub Pages에 시뮬레이터 배포 → 링크 제공 |

완료 기준: 시뮬레이터 링크에서 부팅 화면 → 메인 메뉴 이동이 키보드로 동작.

---

## Phase 1 — MVP: 단일서명 무상태 서명기

목표: SeedSigner 수준의 **무상태 단일서명 서명기**를 QWERTY UX로.

### 1A. 암호 코어 (`bp-crypto`)
- SHA-256, SHA-512, RIPEMD-160, HMAC, PBKDF2-HMAC-SHA512, tagged hash
- secp256k1: 필드/스칼라 연산, **상수 시간** 구현, ECDSA(RFC6979, low-S), Schnorr(BIP-340)
- 검증: NIST/BIP 공식 테스트 벡터 + Wycheproof 벡터 + 퍼징

### 1B. 비트코인 코어 (`bp-bitcoin`)
- BIP-39 (영문 단어장, 12/24단어, 체크섬, 패스프레이즈)
- BIP-32 HD 파생, xpub/ypub/zpub/tpub 직렬화, SLIP-132
- 주소: P2PKH, P2SH-P2WPKH, P2WPKH, P2TR (Bech32/Bech32m, Base58Check)
- PSBT v0 파서/서명기 (단일서명, 위 4가지 스크립트 타입)
- 거래 분석: 금액·수수료·거스름 검증, **SeedSigner 방식 세분화 경고** (소유권 모순, 음수 수수료, 누락 UTXO, 스크립트 불일치, OP_RETURN 등)

### 1C. QR (`bp-qr`)
- QR 인코더/디코더 (카메라 프레임 → 디코드)
- SeedQR / Compact SeedQR
- BC-UR: bytewords, CBOR, fountain code, `crypto-psbt`, `crypto-account`, `crypto-hdkey`, `crypto-output`
- 애니메이션 QR 출력 (밀도/속도 조절)

### 1D. 기능 & UX
- 시드 생성: TRNG, 주사위(D6/D20, 최소 횟수 검증), 카메라 이미지 엔트로피(품질 추정치 표시), 마지막 단어 계산
- 시드 불러오기: QWERTY 타이핑 + 자동완성, 단어 번호 입력, SeedQR 스캔
- 백업: 단어 표시, 백업 확인 퀴즈, SeedQR 내보내기 + 손으로 옮겨 그리기 가이드
- xpub 내보내기 (UR / 일반 QR), 지문(XFP) 표시
- PSBT 스캔 → 검토 → 서명 → 서명된 PSBT QR 출력
- 주소 검증 (QR 스캔), 주소 탐색기
- 설정: 네트워크(main/test/signet/regtest), 단위(BTC/sats), QR 밀도, 한국어/영어
- 무상태 모드 (전원 끄면 비밀값 소멸)

완료 기준: 시뮬레이터에서 **Sparrow가 만든 PSBT를 서명하고, 그 결과를 Sparrow가 받아들임** (테스트넷/시그넷).

---

## Phase 2 — 지갑 확장 & SD 카드

| 항목 | 내용 |
|---|---|
| 2.1 디스크립터 | BIP-380~386 파서, 체크섬, 지갑 등록 |
| 2.2 멀티시그 | P2WSH / P2SH-P2WSH, **사전 등록 후에만 서명** (CC/Jade 방식), 공동 서명자 검증 |
| 2.3 PSBT v2 | BIP-370 |
| 2.4 QR 포맷 추가 | BBQr (Zlib 포함), Specter 형식, 범용 QR 자동 판별, SettingsQR |
| 2.5 SD 카드 | FAT 파일시스템, PSBT 읽기/쓰기, 파일 관리자, 서명된 tx 저장, SD 제거 알림 |
| 2.6 지갑 내보내기 | Sparrow, Nunchuk, Specter, BlueWallet, Electrum, Bitcoin Core 형식 (QR + SD) |
| 2.7 메시지 서명 | BIP-137, **BIP-322**, 서명 검증, SD 텍스트 파일 서명 |
| 2.8 BIP-85 | 자식 니모닉 12/18/24, WIF, XPRV, HEX, 패스워드 |
| 2.9 개인키 가져오기 | WIF / XPRV 가져오기 및 단일 키 서명 |
| 2.10 고급 기능 토글 | SeedSigner 방식의 고급 기능 숨김, 경고 강도 설정 |

완료 기준: 2-of-3 멀티시그 생성 → 등록 → Sparrow/Nunchuk 연동 서명 성공.

---

## Phase 3 — 보안 저장 & 고급 보안

| 항목 | 내용 |
|---|---|
| 3.1 암호화 저장 | 강한 KDF(Argon2id 후보) + AES-GCM 또는 ChaCha20-Poly1305, 기기 내부 / SD 분리 저장 |
| 3.2 잠금 | 영숫자 패스워드(QWERTY), **피싱 방지 단어**, 로그인 지연, 오입력 횟수 초과 시 삭제 |
| 3.3 Trick PIN | 미끼 지갑(Duress Wallet), 조용히 삭제, 삭제 후 미끼 지갑 열기 (Coldcard 체계) |
| 3.4 Tamper Check Code | 부팅 시 펌웨어/플래시 해시 확인 (Krux 방식) |
| 3.5 암호화 전체 백업 | 설정·지갑 등록 정보·노트 포함, 복원 없이 백업 검증 |
| 3.6 SLIP-39 Shamir | 생성/복원 (Keystone/OneKey 호환) |
| 3.7 Seed XOR | 분할/복원 |
| 3.8 Miniscript | P2WSH miniscript, Taproot miniscript, 정책 뷰 (Krux/Specter 방식) |
| 3.9 다중 시드 보관 | Seed Vault, 패스프레이즈 숨김 지갑 |
| 3.10 부가 도구 | 보안 노트/패스워드, TOTP 인증기, 니모닉 편집기, Tinyseed/Stackbit 입력·출력, 데이텀 도구 |

---

## Phase 4 — 하드웨어 이식

| 항목 | 내용 |
|---|---|
| 4.1 보드 선정 | 무선이 내장되지 않은 SoC/MCU (예: 무선 없는 Pi Zero v1.3, STM32H7, i.MX RT) + 카메라 + SD + 디스플레이 + 키보드 매트릭스 |
| 4.2 HAL 구현 | 디스플레이, 키보드, 카메라, SD, TRNG, 전원 관리 |
| 4.3 보안 부트로더 | **SD로만** 설치/업데이트, **M-of-N 다중 서명 검증** (Specter 방식), 다운그레이드 방지 |
| 4.4 재현 가능 빌드 | Docker/Nix로 동일 바이너리 해시 재현 |
| 4.5 USB 데이터 차단 | (USB 포트가 있다면) 충전 전용 회로로 물리 차단 확인 |
| 4.6 SE 검토 | 보안 칩 사용 여부와 범위 결정 |

---

## Phase 5 — 차별화 기능

8개 레퍼런스 어디에도 없거나 드문 기능입니다.

- **MuSig2** (BIP-327) 서명
- **Silent Payments** (BIP-352) 수신 주소/서명
- **Bitpunk 간 Key Teleport**: ECDH 기반으로 기기끼리 QR로 시드/PSBT를 암호화해 전송
- **Codex32** (BIP-93)

---

## 빌드마다 하는 일

1. 변경사항 커밋 & 푸시 (브랜치 → 검토 후 main 병합)
2. CI 테스트 통과 확인
3. GitHub Pages에 시뮬레이터 자동 배포
4. 링크와 함께 **이번 빌드에서 확인할 항목** 체크리스트 제공
