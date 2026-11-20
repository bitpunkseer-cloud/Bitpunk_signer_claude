# M2 구현 계획 — 키와 주소

상태: **구현 완료 (2026-11-20)** — 아래 "9. 구현 결과" 참고

결정: ① secp256k1은 64비트 4칸(`u128` 곱셈)으로 시작, H3 측정 후 필요하면 최적화 ② Native SegWit·Taproot만 기본 표시, Nested·Legacy는 설정의 Advanced features를 켰을 때 ③ 시드 목록은 지문으로 표시

## 1. 목표

불러온 시드에서 **지문(XFP), 확장 공개키(xpub), 주소**를 만든다.
같은 시드를 Sparrow에 넣었을 때 **지문·xpub·첫 주소가 모두 같으면** 완료.

## 2. 범위

| 포함 | 제외 (다른 마일스톤) |
|---|---|
| RIPEMD-160, HASH160, BIP-340 tagged hash | ECDSA / Schnorr **서명** → M5 |
| secp256k1: 필드·스칼라·점 연산 (상수 시간), 공개키 생성, 압축 직렬화 | QR로 xpub 내보내기 → M3 |
| BIP-32: 마스터 키, 하드닝/일반 파생, 지문, xprv/xpub 직렬화 | 디스크립터·멀티시그 → M7 |
| SLIP-132 (ypub/zpub, 테스트넷 upub/vpub) | 외부 xpub 가져오기(공개키 압축 해제) → M7 |
| Base58Check, Bech32, Bech32m | |
| 주소 4종: P2PKH, P2SH-P2WPKH, P2WPKH, P2TR (BIP-44/49/84/86) | |
| BIP-39 패스프레이즈 입력 (QWERTY) | |
| xpub 보기(텍스트), 주소 탐색기(텍스트) | |
| 시드 표시를 단어 대신 **지문**으로 변경 | |

## 3. 암호 코어 (`bp-crypto`)

### 3.1 secp256k1 설계
| 항목 | 방식 | 이유 |
|---|---|---|
| 필드 원소 (mod p) | 64비트 4칸(limb) + `u128` 곱셈 | 구현이 단순해 검증이 쉬움. 32비트 칩에서 느리면 H3 측정 후 26비트 10칸으로 최적화 |
| 점 덧셈 | **완전(complete) 덧셈 공식** (Renes–Costello–Batina 2015, a=0) | 같은 점·무한원점 같은 예외 분기가 없어 상수 시간 보장이 쉬움 |
| 스칼라 곱 | 4비트 고정 윈도우 + **표 전체를 훑는 상수 시간 선택** | 비밀 스칼라에 따라 메모리 접근·분기가 달라지지 않음 |
| 역원 | 페르마 소정리, 고정 덧셈 사슬 | 입력과 무관하게 같은 연산 순서 |
| 조건 선택 | 직접 만든 `Choice`(마스크) 타입 | `if secret { }` 금지 |
| 비밀값 | 스칼라·개인키는 drop 시 지움 | |

### 3.2 해시
- RIPEMD-160 (공개 테스트 벡터), HASH160 = RIPEMD160(SHA256(x)), BIP-340 tagged hash(`TapTweak`).

## 4. 비트코인 계층 (`bp-bitcoin`)

- **BIP-32**: `HMAC-SHA512("Bitcoin seed", seed)` → 마스터 키. 파생 결과가 무효(IL ≥ n 또는 0)면 규격대로 처리.
  경로 문자열 파싱(`m/84'/0'/0'`), 지문 = HASH160(공개키) 앞 4바이트.
- **직렬화**: xprv/xpub/tprv/tpub + SLIP-132 ypub/zpub/upub/vpub. 네트워크 설정을 따름.
- **주소**

| 종류 | 경로 | 메인넷 예 | 테스트넷/시그넷 | 레그테스트 |
|---|---|---|---|---|
| Native SegWit (P2WPKH) | m/84'/c'/a' | `bc1q…` | `tb1q…` | `bcrt1q…` |
| Taproot (P2TR, BIP-86 키 경로) | m/86'/c'/a' | `bc1p…` | `tb1p…` | `bcrt1p…` |
| Nested SegWit (P2SH-P2WPKH) | m/49'/c'/a' | `3…` | `2…` | `2…` |
| Legacy (P2PKH) | m/44'/c'/a' | `1…` | `m…`/`n…` | `m…`/`n…` |

  코인 타입 `c` = 메인넷 0, 그 외 1. 계정 `a` 기본 0.

## 5. 화면

```
Seeds ─► [73c5da0a (12)] ─► Seed options
                             ├─ Show seed words
                             ├─ Export xpub ─► 스크립트 종류 ─► 계정 번호 ─► xpub 화면(텍스트)
                             ├─ Address explorer ─► 스크립트 종류 ─► 수신/거스름 ─► 주소 목록 ─► 주소 상세
                             ├─ Passphrase ─► 입력 ─► 확인(패스프레이즈 + 새 지문) ─► 적용
                             └─ Discard seed
Tools ─► Address explorer ─► 시드 선택 ─► (위와 동일)
```

| 화면 | 내용 |
|---|---|
| 시드 목록 | `73c5da0a (12)`, 패스프레이즈를 적용하면 `+PP` 표시. 화면에 단어가 노출되지 않음 |
| xpub | 지문, 경로, SLIP-132 키(zpub 등), 디스크립터용 `[73c5da0a/84'/0'/0']xpub…`. 111자는 3줄로 나눠 4글자씩 띄워 표시 |
| 주소 목록 | 한 페이지 10개, ◄►로 페이지 이동, Tab으로 수신/거스름 전환, 인덱스 직접 입력 |
| 주소 상세 | 전체 주소를 4글자씩 끊어 크게 표시(Coldcard 방식), 경로 |
| 패스프레이즈 | QWERTY로 출력 가능한 ASCII 입력, 글자 보이기/숨기기 전환, 확인 화면에서 **패스프레이즈와 새 지문을 같이 보여 주고** 적용 (SeedSigner·Coldcard 방식) |

- 성능: 시드를 불러올 때 PBKDF2(2048회)와 마스터 키 계산을 한 번 하고 결과를 슬롯에 보관(drop 시 지움).

## 6. 테스트 & 검증

| 대상 | 방법 |
|---|---|
| RIPEMD-160 | 공개 테스트 벡터 + 테스트 전용 `ripemd` 크레이트 대조 |
| secp256k1 | kG(k = 1~20, n-1 등 경계값) 공개값, **libsecp256k1(`secp256k1` 크레이트, 테스트 전용)과 무작위 스칼라 1만 개 대조**, 점 덧셈 예외 경우 |
| 상수 시간 | 코드 규칙(비밀값 분기 금지) + 호스트 통계 타이밍 검사(dudect 방식, 참고용). 실제 검증은 H 트랙의 실제 칩에서 |
| BIP-32 | 공식 테스트 벡터 1~5 (선행 0 키, 무효 키 포함) |
| 주소 | BIP-84·86·49·44 공식 벡터, BIP-173·350 Bech32 벡터, Base58Check 벡터 |
| 대조 | 테스트 전용 `bitcoin`(rust-bitcoin) 크레이트와 무작위 경로·시드로 xpub·주소 대조 |
| 화면 흐름 | 패스프레이즈 적용 시 지문 변경, 네트워크 변경 시 접두어 변경 |

## 7. 커밋 단위

1. RIPEMD-160, HASH160, tagged hash
2. secp256k1 (필드·스칼라·점·스칼라 곱) + 대조 테스트
3. Base58Check, Bech32/Bech32m
4. BIP-32 + 경로 + SLIP-132 직렬화
5. 주소 4종 + BIP-44/49/84/86 벡터
6. 화면: 지문 표시, 패스프레이즈, xpub 보기, 주소 탐색기
7. 시뮬레이터 배포 + 확인 체크리스트

## 8. 완료 기준 (시뮬레이터에서 확인)

`abandon` ×11 + `about` 시드로:
- [ ] 시드 목록에 지문 **`73c5da0a`**
- [ ] Native SegWit 계정 0 xpub = **`zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs`** (BIP-84 공식 벡터)
- [ ] 첫 수신 주소 **`bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`** (BIP-84)
- [ ] Taproot 첫 수신 주소 **`bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`** (BIP-86)
- [ ] 설정에서 Testnet으로 바꾸면 `vpub…`·`tb1…`로 바뀜
- [ ] 패스프레이즈 적용 시 지문이 바뀌고, Sparrow에서 같은 패스프레이즈로 만든 지갑과 일치
- [ ] Sparrow(테스트넷)에 같은 시드를 넣었을 때 지문·xpub·첫 주소 일치
- [ ] CI 전부 통과

## 9. 구현 결과

| 항목 | 결과 |
|---|---|
| secp256k1 대조 | libsecp256k1과 무작위 키 2,000개 이상 + 경계값 64개, 스칼라 덧셈·부호 반전·점 트윅 모두 일치 |
| 상수 시간 | 타이밍 검사에서 처음엔 k=1이 4% 빨랐음(t = −14.7): 컴파일러가 마스크 선택을 비밀값 분기로 되돌림. `subtle` 크레이트와 같은 volatile 장벽을 넣은 뒤 반복 측정 |t| < 1. 실제 칩에서 다시 측정 예정 |
| BIP-32 | 공식 벡터 1~5 (무효 키 16개 거부 포함), Trezor 루트 키 24개 |
| 주소 | BIP-84·86·49 공식 벡터, BIP-44 첫 주소, rust-bitcoin과 40개 시드 × 4개 네트워크 × 4종 주소 대조 |
| 화면 | 시드 목록 지문 표시, 패스프레이즈(입력·숨김·확인·적용), xpub(SLIP-132 + 디스크립터 키), 주소 탐색기(목록·상세) |
| 성능 메모 | 화면을 그릴 때마다 계정 키를 다시 파생함(시뮬레이터에서는 문제없음). 실제 칩에서 느리면 캐시 추가 (H3) |
