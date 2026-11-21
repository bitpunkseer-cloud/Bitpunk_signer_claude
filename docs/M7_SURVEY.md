# M7 전수조사 — 멀티시그 · 디스크립터

9개 레퍼런스의 멀티시그 코드를 직접 읽고 정리했다 (M5·M6 조사와 같은 저장소 + embit `2b375a3`(2026-09-18), 히스토리 252개 커밋). 참고 외부 자료: BIP-48, BIP-67, BIP-129(BSMS), BIP-174, BIP-370, BIP-380~386·389, BIP-388, SLIP-132, BCR-2020-010/015(UR `crypto-output`·`crypto-account`).
목적: **보안을 최대로** 하는 등록·서명 규칙을 고르고, 사용자의 기존 서명기 3대(SeedSigner·Krux·Specter DIY)가 모두 **embit 한 라이브러리**에 기대는 구조에서 Bitpunk가 어디서 독립성을 보태야 하는지 확인하기 위함. 코드는 참고만 하고 복사하지 않는다.

| 약어 | 프로젝트 | 읽은 곳 |
|---|---|---|
| CC | Coldcard | `shared/multisig.py`(등록·검증·중복 판정·신뢰 정책), `shared/psbt.py`(입력 재구성·거스름 판정), `testing/test_multisig.py`(시험 86개, 이름과 시나리오만) |
| JD | Jade | `main/signer.c`(`validate_signers`), `main/process/register_multisig.c`, `main/process/sign_psbt.c` |
| SP | Specter DIY (embit) | `apps/wallets/manager.py`(지갑 파싱·등록·출력 판정·서명), `apps/wallets/wallet.py` |
| SS | SeedSigner (embit) | `models/psbt_parser.py`(claimed/verified 모델, 거스름 검증), `views/psbt_views.py`(디스크립터 불러오기) |
| KX | Krux (embit) | `krux/wallet.py`(지갑 불러오기·정책 판정), `krux/psbt.py`(검증·출력 분류·서명) |
| PP | Passport Prime | ngwallet `src/psbt/multisig.rs`, `tests/psbt_multisig_security.rs`(공격 시험), KeyOS `ui/pages/import-multisig` |
| KS | Keystone 3 | `rust/apps/bitcoin/src/multi_sig/wallet.rs`(지갑 파일 가져오기·"내 지갑 아님" 검사) |
| OK | OneKey Pro (Trezor 엔진) | `core/src/apps/bitcoin/multisig.py`, `sign_tx/tx_info.py`·`matchcheck.py`(멀티시그 지문 비교) |
| EB | embit | `descriptor/`(파서·`sortedmulti`·체크섬), `psbt.py`(`sign_with`), `CHANGELOG.md`, 커밋 히스토리 |

## 1. 지갑 등록 (descriptor / 지갑 파일 → 기기)

### 1.1 프로젝트별

| | 등록 필요? | 등록 없이 멀티시그 입력 | 거스름 판정 기준 | 저장 |
|---|---|---|---|---|
| CC | **필요** (신뢰 정책: Verify Only / Offer Import / Trust PSBT, 지갑이 하나라도 있으면 기본 Verify) | **거부** ("Unknown multisig wallet") | 등록된 지갑으로 재구성한 스크립트와 **정확히 같을 때만**, 아니면 `FraudulentChangeOutput`(치명) | 내부 플래시 |
| JD | 권장 (등록 기록) | 서명은 하되 **거스름 판정을 포기**(모든 출력을 외부로 표시) | 등록 지갑과 일치할 때만 | 내부 플래시 |
| SP | **필요** (descriptor 가져오기) | 서명 안 함 ("We didn't add any signatures! … forgot to import the wallet?") | 지갑 하나에서만 입력이 올 때, 가지 1(change), 재유도한 scriptPubKey 일치, 간격(gap) 넘으면 경고 | 내부 플래시 |
| SS | **선택** (세션마다 descriptor 스캔) | 서명함. 거스름은 "검증 안 됨" | descriptor가 있으면 그것으로 재유도해 비교, 없으면 모양(스크립트 종류·m-of-n)만 비교 | 없음 (상태 없는 기기) |
| KX | **선택** (descriptor 불러오기) | 서명함. PSBT의 xpub으로 정책을 만듦 | 지갑이 있으면 `descriptor.owns`, 없으면 모든 출력을 지출로 | 없음 (세션마다 불러오기) |
| PP | **필요** (가져온 설정) | 거부 (poisoned input 시험) | 등록 설정으로 재구성할 때만. "발견 모드"는 descriptor를 보여 주지만 **거스름은 절대 인정 안 함** | 내부 플래시 |
| KS | 필요 (Coldcard·Sparrow 지갑 파일) | — | 등록 지갑 기준 | 내부 플래시 |
| OK | **없음** (상태 없음) | 입력마다 xpub 목록을 받아 서명 | 출력의 멀티시그 지문(m + 정렬된 xpub)이 **모든 입력의 지문과 같을 때만** | 없음 |

### 1.2 등록 시 검사 (가장 엄격한 것 모음)

| 검사 | CC | JD | SP | KX | PP | KS |
|---|---|---|---|---|---|---|
| 이 시드의 키가 들어 있어야 함 | ✓ (**정확히 한 번**) | ✓ (공개키+체인코드 비교) | 경고 후 허용(감시 전용) | ✓ | ✓ | ✓ ("내 지갑 아님") |
| 이 시드 지문의 xpub이 실제로 이 시드에서 유도되는지 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 같은 키가 지문 둘 아래 / 다른 키가 우리 키와 같음 | ✓ 거부 | — | — | — | — | — |
| 중복 키 | ✓ | — | — (BIP-388은 금지) | — | — | — |
| xpub 깊이 = 경로 길이, 깊이 1이면 부모 지문 = 마스터 지문 | ✓ | — | — | — | — | — |
| xpub 뒤 경로에 하드닝 금지 | ✓ | ✓ | — | — | — | — |
| M/N 범위 | 1..15 | ✓ | ✓ | 1 ≤ m ≤ n | ✓ | ✓ |
| BIP-67 정렬(`sortedmulti`) | **기본 필수**, 비정렬은 설정으로만 | — | 둘 다 | 둘 다 | 정렬만 | — |
| 네트워크 일치 | ✓ | ✓ | ✓ ("Some keys don't belong to the … network") | ✓ (정책 불일치 경고) | ✓ | ✓ |
| 같은/비슷한 지갑 판정 (M 다름, 주소 종류 다름, 같은 xpub) | ✓ | 같으면 생략, 덮어쓰면 경고 | 같은 descriptor 거부 | — | — | — |
| 서명자별 확인 화면 (지문·경로·xpub) | ✓ | ✓ | ✓ (`ConfirmWalletScreen`) | ✓ | ✓ | ✓ |
| 첫 주소 대조 | — | — | — | — | — | — (BSMS는 첫 주소를 씀) |

### 1.3 가져오기 형식 (사용자 도구 기준)

| 형식 | 쓰는 곳 |
|---|---|
| 디스크립터 텍스트 `wsh(sortedmulti(2,[fp/48h/0h/0h/2h]xpub…/<0;1>/*,…))#체크섬` | Sparrow, Bitcoin Core, Specter, SS, KX, SP, Nunchuk |
| `/0/*` 형식(거스름은 `/1/*`로 간주) | 옛 Specter·Sparrow 내보내기 |
| JSON `{"label":…, "descriptor":…}` | Specter Desktop, Sparrow, KX |
| Coldcard 텍스트 (`Name:` `Policy: 2 of 3` `Derivation:` `Format: P2WSH` + `XFP: xpub` 줄) | CC, Sparrow, Nunchuk, KS, BlueWallet |
| UR `crypto-output`(태그 401 wsh·400 sh·407 sorted-multisig) / UR `bytes`(텍스트 파일) | Sparrow, KS, PP, SS |
| BBQr (U/J) | CC Q, Sparrow, KX |
| BSMS 2단계 (BIP-129) | CC, Nunchuk (Sparrow 미지원) |

## 2. 서명 (멀티시그 PSBT)

| 단계 | CC | SP | SS | KX | PP | OK |
|---|---|---|---|---|---|---|
| 입력 스크립트 판정 | 등록 xpub에서 N개 공개키를 **모두 재유도**(xpub 깊이 뒤 하드닝 금지) → BIP-67 정렬 → 스크립트 해시 = UTXO scriptPubKey | descriptor `owns` | witness/redeem 스크립트를 해시해 scriptPubKey와 비교, 우리 키가 실제로 스크립트에 있는지 | 입력 정책이 모두 같아야("mixed inputs" 거부), 지갑 정책 = PSBT 정책 | 스크립트 정확 분해(`OP_m <키>… OP_n OP_CHECKMULTISIG`), 등록 계정으로 재구성 | 입력의 멀티시그 지문 |
| PSBT 한 장에 지갑 하나 | ✓ | 여러 지갑이면 경고 | — | ✓ (정책 하나) | ✓ | ✓ |
| redeem/witness 스크립트 없음 | 치명 | — | 치명 | — | 치명 | — |
| 다른 계정(account 1')의 같은 서명자 | 다른 지갑 | 다른 지갑 | — | — | **외부로** (시험) | 다른 지문 |
| 경로 메타데이터 불일치(키마다 다른 인덱스) | — | 의심 표시 | 모순(공격) | — | **외부로** (시험) | — |
| 서명 키 선택 | 등록 지갑 + 우리 경로 | embit `sign_with` | embit `sign_with` | embit `sign_with` | 등록 계정 | 입력 경로 |

**Passport 공격 시험** (그대로 우리 시험 시나리오로 옮길 가치가 있음): 공격자 xpub을 전역 xpub에 넣은 거스름(SFT-7394) → 외부, 등록 키만으로 문턱을 낮춘 인질형 → 외부, 다른 계정의 같은 서명자 → 외부, 우리 키가 든 공격자 1-of-2 입력(poisoned input) → 입력 거부, 메타데이터가 불완전한 2-of-2·불가능한 2-of-1 → 패닉 없이 거부, 경로가 서로 다른 출력 → 외부.

## 3. embit 공통 의존 분석 (사용자 구성의 핵심 위험)

사용자의 SS·KX·SP는 앱 계층 검사는 각자 다르지만, 아래는 **모두 embit 한 벌**이 한다. 여기에 버그가 있으면 세 기기가 **동시에 같은 방식으로** 속는다 (공통 모드 장애).

| 계층 | embit이 하는 일 | 세 기기 공통? |
|---|---|---|
| PSBT 파싱 | 키-값 맵, 중복 키, 버전(v0/v2) | ✓ |
| 디스크립터 파싱 | `wsh`/`sh(wsh)`/`sortedmulti` 문법, 체크섬, 다중 경로 `<0;1>` | ✓ |
| BIP-32 | 유도, 지문, xpub 버전 | ✓ |
| 서명 해시 | BIP-143(P2WSH) 스크립트 코드·금액 | ✓ |
| 서명 키 선택 | `sign_with`: 지문이 맞는 **모든** 입력에 서명, 경로의 공개키가 다르면 예외. 지갑 소속 판정은 **앱 몫** | ✓ |
| ECDSA | libsecp256k1 바인딩(RFC 6979 논스) | ✓ (C 라이브러리 + embit 래퍼) |

**근거 — 최근에도 파서 계층 수정이 이어짐** (embit CHANGELOG·커밋):
- 0.8.1(2026-06-01): `tr(...)`, `sh(wsh(...))`, `wsh(...)`, `sh(wpkh(...))` 등 **디스크립터 파서 오프셋 처리 수정**, 브랜치 개수 수정, miniscript `t:` 검증 수정, `assert`를 명시적 오류로 교체
- 0.8.2(2026-08-08): PSBT 전역 버전·개수 충돌 거부, 키 순서와 무관하게 v2 전역 tx 거부
- 2026-09-17: "reject short reads and bound PSBT values", 2026-09-18: 전역 tx의 scriptSig 비어 있어야 함
- 기기마다 embit 버전을 고정해 펌웨어에 넣으므로, 수정이 **기기별로 늦게·제각각** 반영된다.

**결론:** 2-of-3에서 서명 두 개가 모두 embit 기기에서 나오면 embit 버그 하나로 지출 승인 두 개가 함께 뚫릴 수 있다. 다양성이 실제로 효과를 내려면 **매 지출마다 Bitpunk가 두 서명자 중 하나**여야 한다 (2-of-3 정책만으로는 강제되지 않음 → 사용 절차로 지키고, 강제는 M10 miniscript로 가능: 예 `and(Bitpunk, 1-of-나머지)` + 시간잠금 복구). Bitpunk는 PSBT·디스크립터 파서, BIP-32, 서명 해시, secp256k1(자체 Rust 구현, M5에서 libsecp256k1과 바이트 일치 확인)까지 **전 계층이 독립**이어야 하며, 시험에서 embit은 **바깥 오라클**(출력 비교)로만 쓴다.

## 4. 표준 정리

| 표준 | M7에 쓰는 내용 |
|---|---|
| BIP-48 | `m/48'/coin'/account'/script'`, script 2' = P2WSH, 1' = P2SH-P2WSH |
| BIP-67 | 압축 공개키를 바이트 사전순으로 정렬한 `OP_m … OP_n OP_CHECKMULTISIG` |
| BIP-380~383 | 키 표현식(`[지문/경로]xpub/…`), 체크섬(8자 BCH), `sh`/`wsh`/`multi`/`sortedmulti` |
| BIP-389 | 다중 경로 `<0;1>/*` (받기·거스름 한 줄) |
| BIP-388 | 지갑 정책 = 템플릿(`@0/**`) + 키 정보 목록. **중복 키 금지**, 모든 키는 xpub + 하드닝 없는 뒤 경로. 등록 결과를 기기에 저장하거나 **등록 증명(HMAC)** 으로 돌려줌 (Ledger: 정책 해시에 SLIP-21 키로 HMAC, 서명할 때 호스트가 HMAC을 같이 보냄 → **기기에 저장 공간이 없어도 등록 강제 가능**) |
| BIP-129 (BSMS) | 1단계: 서명자 키 기록 `BSMS 1.0 / TOKEN / [fp/path]xpub / 설명 / 서명`(키 소유 증명). 2단계: 코디네이터가 descriptor + 경로 제한 + **첫 주소**를 보내고 서명자가 자기 키·첫 주소를 확인. 암호화는 PBKDF2-SHA512 + AES-256-CTR + HMAC. Sparrow 미지원 |
| BIP-174 | 전역 xpub(`0x01`), 입력·출력 `bip32_derivation`, `witness_script`, `redeem_script`, `partial_sig` |
| BIP-370 | PSBT v2 (CC·JD 지원, Sparrow 기본은 v0) |
| SLIP-132 | `Zpub/Vpub`(P2WSH), `Ypub/Upub`(P2SH-P2WSH) — 스크립트 종류와 어긋나면 혼동 공격 여지 |

## 5. 위협 목록과 레퍼런스의 대응

| # | 위협 | 대응한 곳 |
|---|---|---|
| T1 | 지갑 생성 때 코디네이터가 공동서명자 xpub을 바꿔치기 (인질·도난) | 서명자별 확인 화면(전부), CC의 SD 기반 에어갭 생성 |
| T2 | 받기 주소 바꿔치기 | 기기에서 멀티시그 주소 표시·검증 (CC, JD, SP, PP) |
| T3 | 거스름 위장 (다른 공동서명자, M 낮추기, 다른 계정, 인질형) | 등록 지갑으로 재구성 (CC, PP, SP), 지문 비교 (OK) |
| T4 | 우리 키가 든 공격자 지갑 입력 (poisoned input) | 미등록 거부 (CC, PP, SP) |
| T5 | PSBT 메타데이터 거짓 (경로·공개키·잉여 항목) | claimed/verified 분리 (SS), 재구성 (CC, PP) |
| T6 | 스크립트 종류 혼동 (P2WSH ↔ P2SH-P2WSH, Zpub ↔ Ypub) | 등록 기록의 종류 고정 (CC, KS) |
| T7 | 네트워크 혼합 | 전부 |
| T8 | 중복 키 / 우리 키 두 번 / 같은 키 다른 지문 | CC |
| T9 | xpub 깊이 거짓, xpub 뒤 하드닝 | CC, JD, OK |
| T10 | 저장 공간이 없는 기기에서 세션 사이 descriptor 변조 | Ledger의 등록 HMAC (BIP-388) — SS·KX는 대응 없음(매번 사용자가 확인) |
| T11 | 같은 키에 M만 다른 비슷한 지갑으로 혼동 | CC의 비슷한 지갑 판정 |
| T12 | 라이브러리 공통 모드 장애 (embit) | 독립 구현 + 절차 (3장) |
| T13 | 다른 서명자의 부분 서명이 잘못됨 / 지갑 밖의 키 | 레퍼런스 대부분 검사 안 함 |
