# M3 구현 계획 (v2) — QR 출력 엔진

상태: **구현 완료 (2026-11-20)** — 아래 "9. 구현 결과" 참고 · 근거: [QR_SURVEY.md](../QR_SURVEY.md)

## 0. v1에서 바뀐 점

v1은 "QR을 띄운다" 수준이었다. 100% 에어갭 기기에서는 QR이 주 통신 수단이므로, 레퍼런스 8곳에 흩어진 QR 기능과 성능 요소를 한데 모은 **QR 출력 엔진**으로 확장한다.

| 추가 | 가져온 곳 |
|---|---|
| BBQr (zlib 압축 포함, 압축기 직접 구현), Specter `pM/N` | CC, SS, KX (v1에서는 M6) |
| 프레임 수 자동 최소화 | CC (QR 버전 선택), KX |
| QR을 보는 중 실시간 밀도 전환 + 단계 표시 | PP |
| 프레임 속도 3단계 | JD |
| QR 밝기 조절, 흑백 반전, 전체 화면, 일시 정지 | SS, CC, KS |
| UR 옛 이름 / 새 이름 모두 지원 구조 | PP |
| `crypto-output` 형식 xpub 내보내기 | SS, KX, KS, PP |
| 옮겨 그리기 가이드에 한 줄씩 모드 추가 | KX |
| **자동 스캔 성능 시험대** (흐림·잡음·기울임을 넣어도 읽히는지 측정) | 새로 제안 |

## 1. 목표

- Sparrow가 시뮬레이터 화면의 xpub QR을 읽어 관찰 전용 지갑을 만들고, 주소가 기기와 같을 것.
- 같은 데이터를 **UR·BBQr·Specter·정적** 어떤 형식으로 내보내도 독립 디코더가 원문을 정확히 복원할 것.
- 스캔 성능 시험대에서 기본 설정이 흐림·잡음·기울임 조건을 견딜 것 (수치 목표는 6장).

## 2. 범위

| 포함 | 제외 (다른 마일스톤) |
|---|---|
| QR 인코더 (버전 1~40, 오류 정정 L/M/Q/H, 숫자·영숫자·바이트 모드, 마스크 자동 선택) | 카메라로 읽기, 형식 자동 판별 → M4 |
| QR 표시 엔진 (아래 4장) | `psbt` 내보내기 → M5 (엔진은 그대로 사용) |
| UR: bytewords, CBOR, fountain 인코더, `crypto-hdkey`·`crypto-keypath`·`crypto-account`·`crypto-output`·`bytes` | `crypto-multi-accounts`(멀티코인 앱용) — Bitcoin 전용이라 제외 |
| BBQr 인코더 (H·2·Z, deflate 압축기 직접 구현) | QR 이미지를 microSD에 저장 → M8 |
| Specter `pM/N` 인코더 | 암호화 시드 QR, Key Teleport → M10·M12 |
| xpub QR(4가지 형식), 주소 QR, SeedQR 2종 + 옮겨 그리기 가이드 | SeedQR 다시 스캔해서 확인 → M4 |

## 3. QR 인코더 (`bp-qr`)

| 항목 | 내용 |
|---|---|
| 규격 | ISO/IEC 18004 (QR Code Model 2) |
| 모드 | 숫자, 영숫자, 바이트. 데이터에 맞춰 가장 작은 모드 자동 선택 |
| 오류 정정 | Reed–Solomon (GF(256)), L/M/Q/H |
| 마스크 | 8개 마스크의 감점 규칙 4가지를 계산해 최솟값 선택 |
| 메모리 | 할당 없음, 최대 177×177 모듈 고정 버퍼 |

## 4. QR 표시 엔진 (모든 QR 화면이 공유)

| 기능 | 키 | 출처 |
|---|---|---|
| 정수 배율로 최대 크기, 여백 4모듈 | — | 공통 |
| **밀도** Auto / Low / Medium / High — 보는 중에 바로 바뀌고 점으로 단계 표시. Auto = 데이터 크기를 보고 프레임 수가 가장 적은 크기 선택 | ◄ ► | PP + CC |
| **프레임 속도** Slow / Normal / Fast (약 800 / 450 / 270ms) | Tab | JD |
| **QR 밝기** 배경 흰색의 밝기 단계 (상대 카메라가 눈부셔 못 읽는 문제) | ▲ ▼ | SS |
| **전체 화면** (상태바·안내 숨기고 QR만 최대로) | Enter | KS |
| **일시 정지** / 다시 재생 | Space | CC |
| **흑백 반전** | I | CC |
| 진행 표시 (현재 조각 / 전체, 형식 이름) | — | 공통 |
| xpub 내보내기 기본값: 낮은 밀도 + 느린 속도 (신뢰성 우선) | — | JD |

## 5. 애니메이션 형식과 내보내기

| 형식 | 내용 |
|---|---|
| **UR** | BCR-2020-005/012 규격. fountain 조각 조합에 규격의 Xoshiro256** 사용. 이름은 호환성이 가장 넓은 옛 이름(`crypto-account` 등)을 기본으로 내보내고, 새 이름도 같은 코드로 낼 수 있게 설계 |
| **BBQr** | 헤더 `B$` + 인코딩 + 파일 종류 + 전체 수 + 번호. 인코딩 Z(zlib+Base32)는 **deflate 압축기를 직접 구현**해 프레임 수를 줄임 |
| **Specter** | `p1of3 …` 형식 (Specter Desktop) |

| 내보내기 | 형식 |
|---|---|
| xpub | ① UR `crypto-account` (기본: Sparrow·Nunchuk·BlueWallet·Keeper) ② UR `crypto-output` ③ 정적 텍스트 `[지문/경로]zpub…` ④ Specter `pM/N` |
| 주소 | bech32는 대문자로 인코딩해 QR을 작게 (BIP-173 권장) |
| SeedQR | Standard(숫자 모드) / Compact(바이트 모드), 경고 화면 후 표시 |
| 옮겨 그리기 가이드 | ① 5×5 블록 확대 (SS) ② 한 줄씩 모드 (KX). 방향키로 이동, 좌표 표시 |

## 6. 테스트 & 성능 측정

| 대상 | 방법 |
|---|---|
| QR 인코더 | 테스트 전용 `qrcode` 크레이트와 같은 버전·레벨·마스크에서 **모듈 행렬 완전 일치** + 독립 디코더 2종(`rqrr`, `rxing`)으로 복원 확인 |
| UR | BCR 규격 예제 + 테스트 전용 `ur` 크레이트로 **조각 일부를 버려도** 전체 복원되는지 (fountain 특성) |
| BBQr | Coinkite의 BBQr 참조 구현(Python, 테스트 도구로만)으로 만든 벡터와 대조 + 우리 deflate 결과를 테스트 전용 `miniz_oxide`로 풀어 원문 확인 |
| Specter | 형식 규칙 단위 테스트 |
| SeedQR | SeedSigner `test_seedqr.py` 벡터 |
| crypto-account / output | BCR-2020-015/010 예제 + "abandon…about" 시드 값을 디코더로 되읽어 xpub·경로·지문 확인 |
| **스캔 성능 시험대** | 시뮬레이터 프레임버퍼의 QR 화면을 휴대폰 카메라처럼 축소·흐림·잡음·기울임 처리한 뒤 `rqrr`로 읽어 성공률 측정. 밀도·배율별 표를 만들어 Auto 기본값 결정에 사용. 목표: 기본 설정에서 중간 수준 흐림·잡음·15° 기울임에도 95% 이상 성공 |

## 7. 커밋 단위

1. QR 인코더 + 대조 테스트
2. SeedQR · Compact SeedQR
3. CBOR · bytewords · UR fountain 인코더
4. UR 타입 (`crypto-hdkey/keypath/account/output`)
5. deflate 압축기 + BBQr, Specter `pM/N`
6. QR 표시 엔진 (밀도·속도·밝기·전체 화면·정지·반전·진행 표시)
7. 화면: xpub QR(4형식), 주소 QR, SeedQR + 옮겨 그리기 가이드
8. 스캔 성능 시험대 + 결과 표
9. 시뮬레이터 배포 + 확인 체크리스트

## 8. 완료 기준

`abandon` ×11 + `about` 시드로:
- [ ] xpub → Native SegWit → UR `crypto-account`: **Sparrow로 스캔해 지갑 생성**, 지문 `73c5da0a`, 첫 주소 `bc1qcr8te…`
- [ ] 정적 텍스트 QR을 휴대폰으로 읽으면 `[73c5da0a/84h/0h/0h]zpub6rFR7y…`
- [ ] QR 화면에서 ◄►(밀도)·Tab(속도)·▲▼(밝기)·Enter(전체 화면)·Space(정지)·I(반전) 동작
- [ ] 주소 QR, SeedQR(`0000…0003`)을 휴대폰으로 읽으면 화면 값과 같음
- [ ] 옮겨 그리기 가이드: 블록 모드·줄 모드 이동
- [ ] 스캔 성능 시험대 결과 표가 문서에 기록되고 목표 달성
- [ ] CI 전부 통과

## 9. 구현 결과

| 항목 | 결과 |
|---|---|
| QR 인코더 | 버전 1~40, 숫자·영숫자·바이트, ECC L/M/Q/H. Nayuki `qrcodegen`과 **모듈 행렬 완전 일치**(마스크 지정·자동 선택 모두), `rqrr`·`rxing` 두 디코더로 전 버전 × 3모드 복원 |
| SeedQR | SeedSigner 벡터 6개 (Standard·Compact, 12·24단어) 일치 |
| UR | bytewords·CRC32·fountain(Xoshiro256**) 조각이 `ur` 크레이트와 바이트 일치, 조각을 3개 중 1개씩 버려도 참조 디코더가 복원. 규격 Python/C++ 구현과 `ur` 크레이트가 다른 경계 사례 1건은 규격 구현을 따름 |
| crypto-account / output | embit + urtypes로 만든 벡터 16개(4종 스크립트 × 메인넷·테스트넷 × 계정 0·1)와 바이트 일치 |
| BBQr · deflate | Coinkite 참조 구현 벡터와 일치, 우리 Z 조각을 참조 `join.py`로 복원, 우리 deflate 출력을 `miniz_oxide`로 풀어 원문 확인 |
| 화면 | xpub QR 4형식, 주소 QR, SeedQR 2종(경고 화면 후) + 옮겨 그리기 가이드(블록·줄), QR 표시 엔진(밀도·속도·밝기·전체 화면·정지·반전·진행 표시) |
| 스캔 시험대 | 기본 화면, medium 조건, 기준 거리에서 **98.2%** (목표 95%). 표와 결정 사항: [QR_SCAN_BENCH.md](../QR_SCAN_BENCH.md) |

### 계획과 달라진 점

| 계획 | 실제 | 이유 |
|---|---|---|
| 대조용 `qrcode` 크레이트 | Nayuki `qrcodegen` | 여러 언어 QR 라이브러리의 참조 구현이고, 마스크를 지정해 행렬을 그대로 비교할 수 있음 |
| 밀도 = 최대 QR 버전, Auto = 프레임 수 최소 | 밀도 = **최소 모듈 크기**(Low 8px · Medium 6px · High 5px), **Auto = Low**(40프레임 넘으면 한 단계 위) | 시험대에서 모듈 크기가 성공률을 결정함 (버전 8·6px 85% → 버전 6·8px 98%) |
| QR 화면 하단 안내줄 | 안내를 오른쪽 패널로 옮기고 QR 영역 390 → 428px | 같은 이유 |
| BBQr를 M3 화면에서 사용 | 인코더만 구현·검증, 화면 사용은 M5 PSBT 내보내기부터 | xpub 내보내기에 BBQr를 받는 지갑이 거의 없음 |
