# M6 전수조사 — 메시지 서명 · 주소 검증 · 설정 · D20 · 한국어

8개 레퍼런스의 코드를 직접 읽고 정리했다 (M5 조사와 같은 저장소, 2026-10~11월 커밋). 참고 외부 자료: Sparrow(`MessageSignDialog.java`, drongo `Bip322.java`·`PSBT.java`), BIP-137, BIP-322(본문·시험 벡터).
목적: M6 기능마다 **프로젝트별 장점을 모두 모아** 가장 안전하고 쓸모 있는 방식을 고르기 위함. 코드는 참고만 하고 복사하지 않는다.

| 약어 | 프로젝트 | 읽은 곳 |
|---|---|---|
| SS | SeedSigner | `models/decode_qr.py`(SignMessageQrDecoder), `views/seed_views.py`(SeedSignMessage*, AddressVerification*), `helpers/embit_utils.py`, `models/settings*.py` |
| CC | Coldcard | `shared/msgsign.py`, `shared/auth.py`(ApproveMessageSign, BIP-322 승인), `shared/psbt.py`(BIP-322·PoR), `shared/ownership.py`, `shared/choosers.py` |
| JD | Jade | `main/process/sign_message.c`, `main/ui/sign_message.c`, `main/qrmode.c`(verify_address) |
| SP | Specter DIY | `apps/signmessage/signmessage.py`, `apps/wallets/manager.py` |
| KX | Krux | `pages/home_pages/sign_message_ui.py`, `pages/home_pages/addresses.py`, `pages/new_mnemonic/dice_rolls.py` |
| KS | Keystone 3 | `rust/rust_c/src/bitcoin/msg.rs`, `rust/apps/bitcoin/src/lib.rs`, 한국어 글꼴 `gui_assets/font/ko/` |
| OK | OneKey Pro (Trezor 엔진) | `core/src/apps/bitcoin/sign_message.py`, `bip322_simple.py`, `verify_message.py`, `apps/common/signverify.py`, `keychain.py` |
| PP | Passport Prime | `apps/gui-app-bitcoin/src/message_signing.rs`, `verify_address.rs`, ngwallet `sign_message.rs`, `account.rs` |

## 1. 메시지 서명

### 1.1 프로젝트별

| | 요청 형식 | 경로 규칙 | 메시지 규칙 | 화면 | 서명 형식 |
|---|---|---|---|---|---|
| SS | `signmessage <경로> ascii:<메시지>` (QR 한 장) | 표준 단일 서명(44/49/84/86, 코인 0/1)만, 사용자 정의 경로 거부, **네트워크 불일치 거부** | `ascii:`만 | 메시지를 **쪽마다** 넘겨 본 뒤 → 경로의 **주소** 확인 → 서명 | Electrum (27+4+recid) |
| CC | `signmessage` QR + JSON + 3줄 텍스트 파일(SD) | 경로 정리(`cleanup_deriv_path`), 주소 형식은 경로의 purpose로 | **인쇄 가능한 ASCII만, 2~240자, 공백 3개 연속 금지, 앞뒤 공백 금지** (UI 함정 방지) | "Ok to sign this?" + 메시지 + 주소 + 경로 | **BIP-137** (주소 종류별 헤더 31/35/39) |
| JD | `signmessage` QR (`ascii:` 대소문자 무시) + USB | 어떤 경로든 (루트 키만 금지) | 길이 제한 없음, 화면은 **192자에서 잘림** | 메시지(1~2쪽) + **메시지 해시** + 경로 (주소 없음) | Electrum. USB에서는 **anti-exfil** |
| SP | `signmessage` + `ascii:` 또는 `base64:`, 경로 앞에 **지문 허용**(`73c5da0a/84h/...`, 다르면 거부) | 검사 없음 | ASCII면 글자로, 아니면 **hex로 표시** | 메시지 + 경로 (주소는 서명 **후**) | Electrum |
| KX | `signmessage` QR, SD 파일(armored), 그리고 **임의 데이터/원시 해시** | 문법 검사만 | 32바이트/64자 hex면 **원시 해시로 서명**(경고 후) | 메시지 + 주소 | Electrum. 탭루트 주소에도 ECDSA(검증 불가) |
| KS | UR `btc-sign-request` + SeedSigner 형식 | 요청의 **지문이 시드와 같아야** 함 | UTF-8 아니면 hex | 메시지 + 주소 | Electrum, 결과 UR `btc-signature` |
| OK | USB 메시지 (QR 없음) | **스크립트 종류별 경로 패턴**, 벗어나면 "알 수 없는 경로" 경고 | 최대 8 KB, 인쇄 불가 글자면 **hex 표시** | 메시지 + 주소 (+ 비표준 표시) | **BIP-137** (`no_script_type`이면 Electrum) |
| PP | `signmessage` QR, 3줄 파일 | 전체 경로 필수, purpose 44/48/49/84/86, **경로 네트워크 = 계정 네트워크**, **경로 계정 = 선택한 계정** | `ascii:`만 | 메시지 + 주소 | 44/49/84: Electrum. **86(탭루트)은 BIP-322 simple로 자동 전환** |

### 1.2 BIP-322

| | 지원 | 내용 |
|---|---|---|
| CC | **PSBT 방식 + Proof of Reserves** | 판정: 출력이 값 0 `OP_RETURN`(스크립트 정확히 `6a`) 하나 + 전역 `0x09` 메시지. 메시지 규칙(ASCII, 탭·줄바꿈 허용, 330자). 거래 버전 0(또는 2)만. 입력 0: **`to_spend` 재계산 txid = prevout**, prevout.n = 0, 금액 0, **non_witness_utxo가 있으면 `to_spend`와 바이트 일치**, 이 시드의 키여야 함. PoR(입력 2개 이상)은 **모든 입력이 이 시드 것**, SIGHASH ALL만, 외부 입력 금지, UTXO 금액 기록·수수료 검사 생략. 승인 화면: "BIP-322 Message"/"Proof of Reserves" + 메시지 + 주소(+ PoR 금액) |
| OK | simple (USB) | P2WPKH(BIP-143), P2TR(BIP-341) |
| PP | simple | 탭루트 경로의 `signmessage` 요청에 BIP-322 simple 서명(base64 witness)으로 응답 |
| Sparrow | PSBT 방식 | "BIP322 (Simple)"을 고르면 `to_sign` PSBT를 UR `crypto-psbt`·BBQr로 보여 줌, 메시지는 전역 `0x09` |
| BIP-322 본문 | 서명기 절차 | 위 판정이 모두 참일 때만 BIP-322로 처리하고, 화면은 "거래"가 아니라 **"주소 X로 메시지 Y에 서명"** |
| SS·JD·SP·KX·KS | 없음 | |

### 1.3 메시지 서명 검증 (남의 서명 확인)

| | 내용 |
|---|---|
| CC | armored 서명 파일 검증(`-----BEGIN BITCOIN SIGNED MESSAGE-----`), 헤더와 주소 종류가 안 맞으면 **경고**(검증은 계속), 파일 다이제스트 확인 |
| OK | `verify_message` (USB) |
| PP | BIP-137 + BIP-322 simple 검증 함수 |
| 나머지 | 없음 |

## 2. 주소 검증 (스캔한 주소가 내 지갑 것인지)

| | 범위 | 찾는 방식 | 결과 |
|---|---|---|---|
| SS | 표준 경로의 **계정 0**, 단일 서명(멀티시그는 디스크립터) | 수신·거스름을 **번갈아** 0번부터, **사용자가 멈출 때까지** | 수신/거스름 + 번호 |
| CC | **계정 0 + 이전에 본 적 있는 계정** + 등록한 멀티시그 | 가지마다 앞 764개, 찾은 흔적을 **플래시에 해시로 캐시**(다음 검색이 빠름), 찾으면 주소를 다시 만들어 **완전 대조** | "Verified" + 지갑 이름 + 경로, **"이 키로 메시지 서명"**, 주소 QR. 못 찾으면 "N개 후보, M개 지갑 검색" |
| JD | 단일 서명: **마지막으로 내보낸 xpub의 계정**, 멀티시그: 등록 지갑 | 먼저 **주소 확인 화면**, **네트워크 일치 검사**, **scriptPubKey로 비교**, 20개씩 진행 표시, 일정 개수마다 **"다음 N개 더?"**, 도중에 계정·가지 변경 | 경로 |
| SP | 디스크립터 지갑 | QR에 **번호가 있어야** 함(`bitcoin:<주소>?index=N`), 그 번호만 계산 | 지갑 + 번호 |
| KX | 불러온 지갑(정책·계정) | 사용자가 수신/거스름 선택, **50개씩**, "더 찾기" | "처음 N개 안에 없음" |
| PP | 계정의 주소 종류 지갑 | **마지막으로 확인한 번호부터 바깥쪽으로** 200개씩, 확인한 번호를 저장 | 찾은 번호, **확인한 범위**(수신·거스름) 표시 |
| KS·OK | QR 주소 검증 없음 | | |

## 3. 설정 · SettingsQR

| | 내용 |
|---|---|
| SS | `settings::v1 이름=값 …` SettingsQR, 모르는 항목 무시, 값 검증. **메시지 서명 설정에는 QR 약어가 없어 QR로 켤 수 없음** (위험한 설정은 기기에서만). 메시지 서명은 **기본 꺼짐**(고급 설정) |
| CC | 수수료 한도 선택: **10%(기본) / 25% / 50% / 제한 없음**. 설정은 기기에 저장 |
| 나머지 | 설정은 기기에 저장, QR 주입 없음 |

## 4. D20 주사위

| | 내용 |
|---|---|
| KX | D20: 값을 `-`로 이어 붙인 문자열의 SHA-256, 최소 30회(12단어)·60회(24단어), 섀넌 엔트로피·연속 차이 분포 검사 |
| SS·CC·JD·PP | D6만 (또는 주사위 없음) |

## 5. 한국어

| | 내용 |
|---|---|
| KS | **Noto Sans KR**, 화면에 쓰는 한글 글자만 골라 굽고(`--symbols`), **2비트 계조**로 크기 절약, 크기별 4종 |
| SS | Noto Sans KR (실행 중 TTF), 한국어는 "(beta)" |
| KX | Noto Sans CJK 24 px 비트맵(BDF) + 작은 화면용 FusionPixel 14 px, `ko-KR` 번역 |
| OK | `ko` 로캘 |

## 6. 프로젝트별 장점과 Bitpunk 채택

| 항목 | 가장 강한 곳 | Bitpunk 채택 |
|---|---|---|
| 메시지 요청 형식 | 전원 `signmessage` | `signmessage <경로> ascii:<메시지>` + **경로 앞 지문 허용**(SP) → 맞는 시드 자동 선택, 없으면 need/found(KS·PP) |
| 경로 규칙 | SS·PP·OK | 전체 경로 `m/{44,49,84,86}'/{코인}'/{계정}'/{0,1}/{번호}`만, **코인 = 네트워크**(SS·PP), 그 밖은 **거부** |
| 메시지 규칙 | CC | **인쇄 가능한 ASCII**, 앞뒤 공백·공백 3개 연속 금지(CC), 길이 제한, 줄바꿈은 눈에 보이게 표시 |
| 메시지 표시 | SS·JD | **모든 쪽을 넘겨 봐야** 다음으로(SS), 잘라서 보여 주지 않음(JD의 약점 보완), **메시지 해시**도 표시(JD) |
| 주소 표시 | SS·CC·OK·PP | 시드에서 파생한 주소 + 경로 + 시드 지문, 마지막 확인은 기본 "취소" |
| 서명 형식 | SS·SP·KX·KS·PP·Sparrow (Electrum) / CC·OK (BIP-137) | Electrum 형식(가장 호환), 탭루트 경로는 **BIP-322 simple로 자동**(PP) |
| 원시 해시 서명 | (KX만 허용) | **금지** — 거래 서명 해시를 메시지로 위장할 수 있음 |
| 서명 후 | (라이브러리 내부) | 서명에서 공개키를 복구해 파생 키와 대조, 키 소거 |
| 키보드 활용 | (CC Q는 SD 파일) | 기기에서 **메시지를 직접 입력**하고 주소 탐색기에서 고른 주소로 서명 |
| BIP-322 PSBT | CC + BIP 본문 | CC의 검사 전부(판정, `to_spend` 재계산, n=0, 금액 0, NWU 바이트 일치, 이 시드 입력, SIGHASH ALL, 거래 버전) + 판정 일부만 맞으면 **공격**(CC) |
| Proof of Reserves | CC | 모든 입력이 이 시드 것일 때만, 금액 합계 표시, 외부 입력 거부 |
| 서명 검증 | CC·PP·OK | armored 형식 QR, Electrum·BIP-137 헤더 + BIP-322 simple, 헤더·주소 불일치는 경고(CC) |
| 주소 검증 범위 | CC·SS | 불러온 시드 전부 × 주소 형식에 맞는 스크립트 × 계정 0 + 이번 세션에 쓴 계정(CC) + 직접 고른 계정(JD) |
| 주소 검증 방식 | JD·PP·SP | 먼저 주소 확인·네트워크 검사(JD), **scriptPubKey로 비교**(JD), QR에 번호가 있으면 그 번호부터(SP), 이번 세션에 마지막으로 찾은 번호 주변부터(PP), 수신·거스름 번갈아(SS), 진행 표시와 "더 찾기"(JD·KX) |
| 주소 검증 결과 | CC·PP | "확인됨" + 시드 + 경로, **확인한 범위** 표시(PP), 주소 QR·**이 주소로 메시지 서명**(CC) |
| 수수료 한도 | CC | 차단선 10%(기본)/25%/50% 선택. "제한 없음"은 두지 않음 |
| SettingsQR | SS | 같은 문법, 우리 접두어. **안전을 약하게 하는 변경(메시지 서명 켜기, 수수료 차단선 올리기)은 QR로 적용하지 않음**(SS의 메시지 서명 원칙을 일반화) |
| D20 | KX | Krux와 같은 해시 입력·최소 횟수 |
| 한국어 글꼴 | KS | Noto Sans KR, 쓰인 글자만, 한글은 2비트 계조(KS) |

## 7. 시험 자료

- BIP-322 `basic-test-vectors.json`, `generated-test-vectors.json` (CC0)
- Bitcoin Core·rust-bitcoin `sign_message` (Electrum 형식 서명은 RFC 6979 결정적이라 바이트 비교 가능)
- Coldcard 메시지 서명·PoR 시험의 상황 (테스트 코드는 MIT+Commons Clause라 복사하지 않고 상황만 재구성)
- Krux D20 계산 방식으로 만든 기대값
