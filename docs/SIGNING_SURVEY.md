# 서명 과정 전수조사 — PSBT 검증·서명

8개 레퍼런스의 PSBT 검증·승인·서명 코드를 직접 읽고 정리했다 (저장소 기준일: 2026-10~11월 커밋).
목적: Bitpunk Signer M5에 **가장 강한 서명 과정**을 고르기 위함. 코드는 참고만 하고 복사하지 않는다.

| 약어 | 프로젝트 | 읽은 곳 |
|---|---|---|
| SS | SeedSigner | `models/psbt_parser.py` (2,215줄), `views/psbt_views.py` |
| CC | Coldcard | `shared/psbt.py` (2,796줄), `shared/auth.py` |
| JD | Jade | `main/process/sign_psbt.c`, `sign_utils.c`, `wallet.c` |
| SP | Specter DIY | `apps/wallets/manager.py`, `keystore/ram.py` |
| KX | Krux | `src/krux/psbt.py` |
| KS | Keystone 3 | `rust/apps/bitcoin/src/transactions/psbt/wrapped_psbt.rs` |
| OK | OneKey Pro (Trezor 엔진) | `core/src/apps/ur_registry/chains/bitcoin/transaction.py`, `apps/bitcoin/sign_tx/` |
| PP | Passport Prime (KeyOS) | `apps/gui-app-bitcoin/src/psbt_signing.rs`, 검증 라이브러리 `ngwallet` (`src/psbt.rs`) |

## 1. 프로젝트별 핵심

### SeedSigner — 가장 세분화된 검증
- **원칙: "PSBT의 키 정보는 주장일 뿐"**. 코드 전체에서 `claimed_…`(호스트가 준 값: 표시만 가능, 판단 금지)와
  `verified_…`(시드에서 다시 파생해 확인한 사실)를 이름으로 구분하고, 다시 파생하지 않고 claimed를 verified로 옮기지 않는다.
- 오류 20여 종을 **"공격"과 "형식 오류"로 나눠** 다른 화면을 보여 준다 (예: "Likely an Attack!" vs "Transaction Problem").
  공격급은 즉시 중단, 가벼운 것은 보류했다가 더 심각한 것이 없을 때 보고.
- 입력: 레거시는 이전 거래(non_witness_utxo) 필수, 있으면 txid 대조, witness_utxo와 모순이면 거부.
  입력이 쓰는 스크립트(redeem/witness)가 빠지거나, 틀리거나, 불필요하게 붙어 있으면 거부.
- 거스름: 출력 스크립트를 시드에서 다시 만들어 맞을 때만 거스름. 경로 규칙 위반(입력과 다른 계정, 0/1 외 분기,
  강화 인덱스, 너무 짧은 경로)은 **거부**. 주소 번호가 입력보다 10,000 이상 크면 경고.
- 수수료: 보내는 금액(거스름 제외)의 25% 초과면 강한 경고. 거스름 없음(전액 지출) 경고. 음수 수수료 거부.
- CVE-2020-14199(segwit v0 다중 서명 라운드 수수료 공격): 위험을 알고도 **경고하지 않음** (지갑들이 이전 거래를 거의 안 넣어 경고가 늘 뜨기 때문).
  단, 입력이 서로 다른 계정이면서 이전 거래가 없으면 거부.
- 서명 후: 서명 수가 늘었는지 확인, 실패면 "Signing Failed". 결과는 **서명만 남긴 축소본**.

### Coldcard — 가장 엄격한 정책과 서명 직전 재검증
- 수수료: **총 출력의 10% 이상이면 기본 차단**(설정으로 조정), 5% 이상 경고. 음수 수수료 차단.
- SIGHASH: NONE·SINGLE **기본 차단**, 순수 통합 거래는 ALL만, 그 외 비표준은 경고.
- 거스름: 파생 정보로 다시 만든 키가 주소와 다르면 "Change Fraud"로 차단. 경로 길이·강화 패턴·접두어·분기(0/1)·
  인덱스(입력 최대 인덱스 + 200 초과) 이상은 경고.
- **서명 직전(승인 후) 거스름 출력을 다시 한 번 재검증** — "느리지만 공격자를 잡는 결정적 단계".
- **UTXO 금액 기억(OutptValueCache)**: 서명했던 segwit UTXO의 금액을 저장해 두고, 같은 UTXO가 다른 금액으로 오면 차단 → CVE-2020-14199 대응.
- 서명: 세션마다 **secp 컨텍스트 무작위화**(부채널 대비), **low-R 그라인딩**(71바이트 서명, Bitcoin Core와 같은 모양 → 서명 크기로 기기 식별 방지),
  서명 직후 개인키 소거. 레거시 입력은 이전 거래 필수. 중복 입력 차단, 이미 다 서명된 거래 차단, 일부 서명됨 경고.
- 기타 경고: OP_RETURN 여러 개 또는 80바이트 초과, 알 수 없는 스크립트 출력, 0원 출력, 수수료를 계산할 수 없는 외부 입력.
- 승인 화면: 보내는 금액·수수료·입출력 수·받는 주소 목록·거스름·locktime·경고를 한 화면(스토리)에 모아 표시.

### Jade
- SIGHASH **ALL만 허용**(탭루트는 DEFAULT도) — 가장 엄격.
- low-R 그라인딩(ECDSA), 탭루트 키 트윅 후 Schnorr(보조 난수 없음 = 결정적). 키 버퍼는 `SENSITIVE_PUSH/POP`으로 소거.
- 수수료가 보내는 금액 이상이면 경고, 입력 스크립트 종류가 섞이면 경고, 표준이 아닌 거스름 경로 경고.
- Anti-exfil(호스트가 넣는 엔트로피로 nonce를 통한 키 유출 방지)은 USB/BLE 호스트 흐름에만 있고, QR 흐름에는 없음.

### Specter DIY
- 지갑(디스크립터) 등록 기반. 등록 안 된 지갑의 입력이 있으면 경고, **여러 지갑의 입력이 섞이면 경고**.
- 비표준 SIGHASH면 목록을 보여 주고 **"기본(ALL)으로만 서명" 선택지**를 줌. 이미 다 서명된 거래 경고.
- 거스름 메타데이터가 지갑과 안 맞으면 경고("Verify the destination").
- **PSBT를 통째로 메모리에 올리지 않는 스트리밍 처리(PSBTView)**, 결과는 서명만 남긴 축소본.

### Krux
- SIGHASH ALL/DEFAULT 외에는 **거부**. 레거시는 이전 거래 필수. 정책이 다른 입력이 섞이면 거부. 출력 > 입력 거부.
- **입력이 2개 이상인 segwit v0 거래에 이전 거래가 없으면 CVE-2020-14199 경고** (SeedSigner와 반대 선택).
- 결과는 서명만 남긴 축소본.

### Keystone 3
- rust-bitcoin의 PSBT 서명 함수를 그대로 사용. 이미 서명된 입력 거부, 이전 거래와 witness_utxo 금액 대조, 수수료 > 송금액 경고.
- 입력 스크립트·파생 경로 검사 함수는 **비어 있음(항상 통과)** — 조사 대상 중 가장 약함.

### OneKey Pro (Trezor 서명 엔진)
- PSBT를 Trezor의 서명 프로토콜로 바꿔 내부의 Trezor 엔진으로 서명.
- **탭루트만 있는 거래가 아니면 모든 입력의 이전 거래를 요구**하고 금액과 scriptPubKey를 대조 — CVE-2020-14199에 대한 가장 강한 대응.
  (탭루트만이면 BIP-341이 모든 금액·스크립트를 커밋하므로 생략.)
- 승인 때와 서명 때 받은 입력이 같은지 해시로 재확인("Transaction has changed during signing").
- 수수료율 상한(코인별 최대 sat/vB) 초과 시 확인, 10배 초과는 차단. 거스름 개수 과다 경고, 기본이 아닌 locktime 확인.

### Passport Prime (KeyOS + ngwallet)
- **엄격한 기본값 + 명시적 해제**: 탭루트가 아닌 segwit 입력에 이전 거래가 없으면 먼저 **"Unable to Verify Inputs"** 화면.
  사용자가 "Temporarily Disable"을 눌러야 그 거래만 검증을 끄고 다시 검증 (BDK 기본 서명 정책과 같은 기준).
- **전역 xpub도 마스터 키로 다시 파생해 검증**(틀리면 Fraudulent Key), xpub·경로의 네트워크 일관성 검사.
- 이전 거래 txid 불일치 → Fraudulent Input, P2PK 거스름 거부(Deprecated), 알 수 없는 출력 스크립트 오류.
- 저장된 계정(디스크립터)을 신뢰 기준으로 사용. "Incorrect Active Key (need X, found Y)"로 지문 불일치를 알려 줌.
- 수수료 비율 표시, 25% 이상 경고. 출력에 "Suspicious"·"Self-Send" 표시. **밀어서 서명(slide to sign)**.
- 서명은 BDK. 키는 zeroize로 소거.

## 2. 항목별 비교 — 가장 강한 선택

| 항목 | 가장 강한 곳 | Bitpunk 채택 |
|---|---|---|
| 신뢰 모델 | SS (claimed/verified) | **Rust 타입으로 강제**: `Verified<T>`는 재파생 함수만 만들 수 있게 해 실수로 섞을 수 없게 함 |
| 레거시 입력 금액 | 전원 | 이전 거래 필수 |
| segwit v0 금액 (CVE-2020-14199) | OK·PP (이전 거래 요구), CC (금액 기억) | **PP 방식 기본 + CC 금액 기억**: 이전 거래가 없으면 차단 화면 → 사용자가 명시적으로 해제할 때만 진행. 전원이 켜져 있는 동안 서명한 UTXO 금액을 기억해 다른 금액이면 차단 |
| 이전 거래 무결성 | SS·KS·PP | txid 대조 + witness_utxo와 일치 확인 |
| 입력 스크립트 | SS | 빠짐·불일치·불필요 스크립트 모두 거부, 우리 키가 실제로 스크립트에 쓰이는지 확인 |
| 소유권 주장 | SS·CC·PP | 입력·출력·**전역 xpub** 모두 재파생 검증, 거짓 주장은 "공격"으로 차단 |
| 거스름 경로 | SS (거부) + CC (경고) | 구조 위반은 거부(SS), 인덱스 창 초과는 경고 |
| 서명 직전 재검증 | CC | 승인 후 서명 직전에 거스름·입력 판정을 다시 계산해 승인 때와 같은지 확인 |
| SIGHASH | JD·KX | ALL(탭루트 DEFAULT)만 허용, 나머지 거부 |
| 수수료 | CC (차단) | 단계별: 경고 → 강한 경고 → 기본 차단 (아래 결정 사항) |
| 기타 경고 | CC·SP·JD | 스크립트 종류 혼합, 여러 계정 혼합, 외부 입력, OP_RETURN, 알 수 없는 스크립트, 0원 출력, 이미 서명됨, 중복 입력, 네트워크 불일치, locktime |
| ECDSA nonce | 전원 RFC 6979 | RFC 6979 + **low-S + low-R 그라인딩** (libsecp256k1과 바이트 일치) |
| Schnorr | JD (결정적) | BIP-340, 보조 난수 0 (결정적). TRNG 섞기는 하드웨어 트랙 |
| 서명 후 검증 | (라이브러리 내부) | **모든 서명을 직접 검증**하고 PSBT의 공개키와 대조 (오류 주입·버그 대비) |
| 부채널 | CC (컨텍스트 무작위화) | 상수 시간 연산(M2) + 타이밍 측정. 무작위 블라인딩은 TRNG가 생기면(H 트랙) |
| 키 소거 | CC·JD·PP | 파생 키·nonce·서명 해시 버퍼를 사용 직후 소거 |
| 최종 승인 | PP (밀어서 서명) | 키보드 기기: 마지막 화면에서 기본 선택을 "취소"로 두고, "서명"으로 옮겨 Enter (실수 방지) |
| 출력 | SS·SP·KX | 서명만 남긴 축소본 + 서명 수 증가 확인 |
| 큰 PSBT | SP (스트리밍) | 원본 위치 색인으로 복사 없이 처리. 32 KB 초과는 "큰 거래" 안내(SD는 M8) |

## 3. 시험 자료

- SeedSigner `tests/test_psbt_parser.py` (MIT): 공격 PSBT를 만드는 시험 125개 → 같은 상황을 Rust 시험으로 옮겨 우리 판정이 같은지 확인.
- Coldcard `testing/data/*.psbt` 37개 (라이선스 확인 필요): 저장소에 넣지 않고 필요할 때 내려받아 시험 (M4의 ZXing 사진과 같은 방식).
- 표준 벡터: BIP-174/371 PSBT, BIP-143/341 서명 해시, BIP-340, RFC 6979, Wycheproof.

## 4. Passport Prime에서 벤치마크할 것 (서명 외 포함)

| 항목 | 내용 | Bitpunk 적용 |
|---|---|---|
| ngwallet 검증 라이브러리 | 전역 xpub 재파생 검증, 네트워크 일관성, 이전 거래 정책 옵션, 사기 입출력 판정 | M5 검증기 설계에 반영 (Rust라 구조 비교가 쉬움) |
| 엄격한 기본값 + 명시적 해제 | "Unable to Verify Inputs" → "Temporarily Disable" | M5 기본 정책 |
| 서명 UX | 밀어서 서명, "Incorrect Active Key (need/found)", "Suspicious"·"Self-Send" 표시, 수수료 비율, "Large Transaction" 선택 | M5 화면 |
| 임시 패스프레이즈 계정 + 이름 | 패스프레이즈 계정에 이름을 붙여 구분 | M6(설정·UX) 후보 |
| 암호 성능 측정 앱 (Crypto Performance) | 기기에서 암호 연산 속도를 안정될 때까지 반복 측정 | 하드웨어 트랙: 서명·파생·QR 디코딩 속도 측정 도구 |
| 엔트로피 시험 앱 | 하드웨어 TRNG에 NIST SP 800-22 검사(monobit·runs·직렬 상관·최소 엔트로피) | 하드웨어 트랙: Schnorr 보조 난수·블라인딩용 TRNG를 넣을 때 검사 도구로 (시드는 계속 주사위·동전만) |
| 펌웨어 서명 cosign2 | `no_std` Rust 이미지 서명 라이브러리·CLI, 서명 헤더 | M11(출시 준비)·SD 업데이트 검증 설계 참고 |
| 재현 가능 빌드 | Nix로 고정한 환경, 공개 바이너리와 바이트 비교 | M11 |
| 마이크로커널·프로세스 격리 (Xous 기반) | 앱별 권한, 서명 앱 격리 | 하드웨어 트랙 아키텍처 참고 (MCU 성능에 맞춰 축소) |
| Casa Health Check | 멀티시그 키가 살아 있는지 서명으로 확인 | M7 이후 후보 |
| 제외 | QuantumLink(BLE), Envoy 연동 | 무선 없음 원칙 |
