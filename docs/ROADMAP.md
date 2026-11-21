# Bitpunk Signer 로드맵 (v2)

- 범위: **Bitcoin 전용** · 100% 에어갭 (무선/NFC/USB 데이터 없음) · 카메라 QR + microSD · QWERTY 키보드
- 언어: Rust, `embit`/`libwally` 등에 의존하지 않는 독자 구현 (기존 라이브러리는 테스트 대조용으로만 사용)
- 근거 문서: [FEATURE_SURVEY.md](FEATURE_SURVEY.md), [HARDWARE_REQUIREMENTS.md](HARDWARE_REQUIREMENTS.md), [ARCHITECTURE.md](ARCHITECTURE.md)
- 진행 규칙: 각 마일스톤은 **구현 계획 제시 → 승인 → 구현 → 커밋/푸시 → 시뮬레이터 링크 제공** 순서로 진행합니다.

## 로드맵 원칙 (v1에서 바뀐 점)

1. **수직 구조.** 암호 → 비트코인 → QR → UX 순서로 층을 쌓지 않습니다. 마일스톤마다 화면에서 쓸 수 있는 기능 하나를 끝까지 완성합니다.
2. **외부 대조로 끝냄.** 각 마일스톤은 Sparrow, SeedSigner, Krux 등 외부 도구와 결과가 같은지 확인하는 것으로 완료됩니다.
3. **하드웨어 트랙을 일찍, 병행해서.** 보안 저장 설계가 칩에 의존하므로 보드는 보안 저장 마일스톤(M9) 전에 확정합니다.
4. **QR 인코더와 디코더 분리.** 쉬운 출력(인코더)을 먼저 해서 xpub 내보내기를 앞당깁니다.
5. **시드는 물리 엔트로피로만.** 시드는 사용자가 굴린 주사위·던진 동전으로만 만듭니다. 기기 난수(PRNG)는 시드 재료로 쓰지 않습니다.
6. **시뮬레이터 시드는 테스트 전용.** 웹 페이지는 에어갭이 아니므로 시뮬레이터에는 "TEST ONLY" 표시를 상시 띄웁니다.

## 의존 관계

```
SHA-256 ─► BIP-39 시드 (M1)
SHA-512·HMAC·PBKDF2 ─┘
secp256k1 + RIPEMD-160 ─► BIP-32 · 지문 · xpub · 주소 (M2)
QR 인코더 ─► xpub/주소/SeedQR 표시 (M3) ─► 지갑 앱이 관찰 전용 지갑 생성
QR 디코더 + UR ─► SeedQR/PSBT 읽기 (M4)
ECDSA·Schnorr + PSBT ─► 서명 → 서명 결과 QR (M5 = MVP)
```

---

## Phase 0 — 기반 구축 ✅ 완료

아키텍처 문서, Rust 워크스페이스(7개 크레이트), 공용 UI 코드(폰트·위젯), 웹 시뮬레이터(기기 외형 + QWERTY),
CI(포맷·clippy·테스트·Cortex-M no_std 빌드·GitHub Pages 배포), Rust 1.97.0 고정.

---

## M1 — 시드 생성 · 입력 ✅ 구현 완료

| 항목 | 내용 |
|---|---|
| 암호 | SHA-256, SHA-512, HMAC-SHA512, PBKDF2-HMAC-SHA512 |
| BIP-39 | 영문 단어장, 엔트로피 ↔ 니모닉, 체크섬, 시드(패스프레이즈 없이) |
| 생성 | **주사위 D6 · 동전만** (값 문자열의 SHA-256). 횟수·추정 엔트로피·치우침·반복 패턴·연속 반복 검사를 실시간 표시하고, 실패 시 생성 불가 |
| 입력 | QWERTY 타이핑 + 자동완성, 단어 번호(1~2048) 입력 |
| 도구 | 마지막 단어 계산기 (무작위로 뽑은 11/23단어 + 동전 7/3회) |
| 백업 | 단어 표시(경고 화면 포함), **전체 단어 객관식 퀴즈** — 통과해야 시드 생성 |
| 기반 | 화면 문자열 표(영어), 텍스트 입력 위젯, "TEST ONLY" 배너 |

**완료 기준:** 공식 BIP-39 테스트 벡터 통과. 같은 주사위 입력으로 SeedSigner·Krux와 같은 엔트로피가 나옴. 엔트로피 부족·퀴즈 실패 시 생성 불가.

## M2 — 키와 주소 ✅ 구현 완료

secp256k1(상수 시간), RIPEMD-160, BIP-32 파생, 지문(XFP), xpub/ypub/zpub/tpub(SLIP-132),
Base58Check·Bech32·Bech32m 주소(P2PKH, P2SH-P2WPKH, P2WPKH, P2TR), BIP-39 패스프레이즈,
주소 탐색기(텍스트), 공식 BIP-32/173/350 벡터 + libsecp256k1 대조 테스트.

**완료 기준:** 같은 시드를 Sparrow에 넣었을 때 지문·xpub·첫 주소가 모두 같음.

## M3 — QR 출력 엔진 (v2, [QR_SURVEY.md](QR_SURVEY.md) 반영) ✅ 구현 완료

QR 인코더(버전 1~40), 표시 엔진(밀도 자동·실시간 전환, 프레임 속도, 밝기, 전체 화면, 정지, 반전),
UR(fountain, `crypto-hdkey/keypath/account/output`), BBQr(zlib 압축 직접 구현), Specter `pM/N`,
xpub QR 4형식, 주소 QR, SeedQR·Compact SeedQR + 옮겨 그리기 가이드(블록·줄 모드), 스캔 성능 시험대.

**완료 기준:** Sparrow가 시뮬레이터 화면의 QR을 읽어 관찰 전용 지갑을 만듦. 모든 형식이 독립 디코더로 복원됨. 스캔 시험대 목표 달성.

**결과:** 스캔 시험대 기준 98.2% (목표 95%), 결과와 결정 사항은 [QR_SCAN_BENCH.md](QR_SCAN_BENCH.md).

## M4 — QR 입력 ✅ 구현 완료

QR 디코더(흑백 프레임 → 데이터), UR fountain 디코딩, SeedQR 스캔, 범용 QR 형식 자동 판별,
시뮬레이터 카메라(이미지 업로드 · QR 텍스트 붙여넣기).

**완료 기준:** SeedSigner로 만든 SeedQR을 읽으면 같은 시드가 나옴.

**결과:** 직접 만든 스캐너가 실사진 90.8% (rxing 86.6%, rqrr 67.9%), 스캔 시험대 기준 거리 98.2%. 상세: [M4_PLAN.md](milestones/M4_PLAN.md) 12장, [QR_SCAN_BENCH.md](QR_SCAN_BENCH.md).

## M5 — PSBT 서명 (MVP) ✅ 구현 완료 (Signet 실송금 확인 대기)

PSBT v0 파서, ECDSA(RFC 6979, low-S)·Schnorr(BIP-340/341) 서명, 거래 검토 화면(금액·수수료·거스름),
SeedSigner 방식의 세분화된 경고(소유권 모순, 음수 수수료, 누락 UTXO, 스크립트 불일치, OP_RETURN 등),
서명된 PSBT 애니메이션 UR QR 출력, Wycheproof 벡터 + 퍼징.

**완료 기준:** Signet에서 Sparrow → Bitpunk → Sparrow 실제 송금 성공.

**결과:** ECDSA·Schnorr가 libsecp256k1과 바이트 일치, Core·BIP·Wycheproof·Coldcard 벡터, SeedSigner 시나리오 같은 판정, 서명을 rust-bitcoin으로 독립 검증, 결과 QR(UR·BBQr·Specter) 왕복. 상세: [M5_PLAN.md](milestones/M5_PLAN.md) 11장, 조사: [SIGNING_SURVEY.md](SIGNING_SURVEY.md).

## M6 — 서명 확장 ✅ 구현 완료

QR로 주소 검증, 메시지 서명(BIP-137, BIP-322) 및 검증, BBQr, Specter 형식, SettingsQR, D20 주사위,
고급 기능 토글·경고 강도 설정, **한국어 UI**(한글 폰트 포함).

**결과:** 주소 검증(scriptPubKey 비교, 모든 시드·세션 계정, 1,000개 단위), Electrum·BIP-137 서명이 rust-bitcoin·Bitcoin Core 벡터와 바이트 일치, BIP-322 공식 벡터 전부(simple 서명·검증, PSBT 판정, 보유 증명), 메시지 서명 기본 꺼짐, 수수료 기준 설정과 약화 금지 SettingsQR, D20, 한국어 UI(377자, 모든 화면 넘침 검사). 상세: [M6_PLAN.md](milestones/M6_PLAN.md) 13장, Sparrow 왕복 방법 14장, 조사: [M6_SURVEY.md](M6_SURVEY.md).

## M7 — 멀티시그 · 디스크립터

출력 디스크립터(BIP-380~386), 멀티시그(P2WSH / P2SH-P2WSH) **사전 등록 후에만 서명**, PSBT v2(BIP-370),
지갑 내보내기(Sparrow, Nunchuk, Specter, BlueWallet, Electrum, Bitcoin Core).

**완료 기준:** Sparrow·Nunchuk에서 2-of-3 멀티시그 생성·등록·서명 성공.

**계획(제안, 승인 대기):** [M7_PLAN.md](milestones/M7_PLAN.md) — 등록된 지갑만 서명, 저장 공간 없이 등록을 묶는 지갑 코드(시드 HMAC), 공동서명자 xpub을 직접 스캔하는 에어갭 생성, embit과 독립인 구현·3중 오라클 시험. 조사: [M7_SURVEY.md](M7_SURVEY.md).

## M8 — microSD

FAT 파일시스템, PSBT 파일 읽기/쓰기, 파일 관리자, 서명된 tx 저장, SD 제거 알림, BIP-85(니모닉·WIF·XPRV·HEX·패스워드),
WIF / XPRV 개인키 가져오기 및 단일 키 서명.

## H — 하드웨어 트랙 (M3부터 병행)

| 항목 | 내용 |
|---|---|
| H1 후보 비교 | 무선이 내장되지 않은 칩만 (예: 무선 없는 Pi Zero v1.3, STM32H7, i.MX RT). 화면·키보드·카메라·SD·TRNG·보안 칩 조합 |
| H2 개발 보드 연결 | HAL 구현: 화면, 키보드 매트릭스, 카메라, SD, TRNG |
| H3 성능 측정 | 실제 칩에서 PBKDF2(2048회), secp256k1 서명, QR 디코딩 시간·메모리 측정 |
| H4 확정 | **M8 종료 전에 보드 확정** → M9 설계 입력 |

## M9 — 보안 저장 (확정된 칩 기준)

암호화 저장(KDF + AEAD, 보안 칩 사용 범위 결정), 영숫자 PIN/패스워드, 피싱 방지 단어, 로그인 지연,
오입력 횟수 초과 시 삭제, Trick PIN(미끼 지갑·조용히 삭제), Tamper Check Code, Seed Vault(다중 시드).

## M10 — 고급 백업 · 도구

암호화 전체 백업 및 검증, SLIP-39 Shamir, Seed XOR(분할에 필요한 무작위 값도 주사위·동전으로 받는 방안 검토), Miniscript(P2WSH·Taproot)와 정책 뷰,
Tinyseed/Stackbit, 니모닉 편집기, 데이텀 도구, 보안 노트·패스워드, TOTP 인증기.

## M11 — 출시 준비

보안 부트로더, **microSD로만** 설치/업데이트, **M-of-N 다중 서명 검증**, 다운그레이드 방지,
재현 가능 빌드(Docker/Nix), USB 데이터 라인 물리 차단 확인, 외부 보안 감사 준비.

## M12 — 차별화 기능

MuSig2(BIP-327), Silent Payments(BIP-352), Bitpunk 간 Key Teleport(ECDH 기반 QR 암호 전송), Codex32(BIP-93).

---

## 빌드마다 하는 일

1. 변경사항 커밋 & 푸시
2. CI 통과 확인 (포맷, clippy, 테스트, no_std 빌드)
3. 시뮬레이터 배포: Claude 아티팩트 갱신 + GitHub Pages 자동 배포
4. 링크와 함께 **이번 빌드에서 확인할 항목** 체크리스트 제공
