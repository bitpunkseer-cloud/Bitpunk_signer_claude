# QR 기능 심층 조사 (2026-11-20)

Bitpunk Signer는 무선·USB·NFC가 없으므로 **QR이 기기와 바깥을 잇는 거의 유일한 통로**다(나머지는 microSD).
8개 레퍼런스의 QR 관련 코드를 다시 조사해 기능과 성능 요소를 정리했다.

- 범례: **●** 있음 · **◐** 일부 · **—** 없음
- 약어: SS=SeedSigner, KX=Krux, SP=Specter DIY, JD=Jade, CC=Coldcard(Q), KS=Keystone 3, OK=OneKey Pro, PP=Passport Prime(KeyOS)

## 1. QR 형식 (주고받는 데이터의 포장 방식)

| 형식 | SS | KX | SP | JD | CC | KS | OK | PP | 근거 / 비고 |
|---|---|---|---|---|---|---|---|---|---|
| 정적 단일 QR (텍스트·바이트) | ● | ● | ● | ● | ● | ● | ● | ● | 모든 기기 |
| Specter `pM/N` 애니메이션 | ● | ● | ● | — | — | — | — | — | KX `qr.py` FORMAT_PMOFN, SS `PSBT__SPECTER`, Specter Desktop 호환용 |
| BC-UR fountain 애니메이션 | ● | ● | ◐ | ● | — | ● | ● | ● | 지갑 앱 대부분이 쓰는 표준 |
| UR 이름: 옛 이름(`crypto-psbt` 등) | ● | ● | ● | ● | — | ● | ● | ● | |
| UR 이름: 새 이름(`psbt`, `hdkey` 등) 동시 인식 | — | — | — | — | — | — | — | ● | PP `normalize_ur_type()`가 두 이름을 같게 취급 |
| **BBQr** (Coldcard 고안) | ● | ● | — | — | ● | — | — | — | CC `bbqr.py`: 파일 종류(P PSBT, T 트랜잭션, J JSON, C CBOR, U 텍스트, B 바이너리), 인코딩(H 16진수, 2 Base32, **Z zlib 압축+Base32**) |

### UR 데이터 타입
| 타입 | SS | KX | JD | KS | OK | PP | 용도 |
|---|---|---|---|---|---|---|---|
| `crypto-psbt` / `psbt` | ● | ● | ● | ● | ● | ● | 서명할 거래 (M5) |
| `crypto-account` | ● | ● | ● | ● | — | ● | 계정 xpub 내보내기 (Sparrow 등) |
| `crypto-output` | ● | ● | — | ● | — | ● | 디스크립터 1개 |
| `crypto-hdkey` / `hdkey` | — | — | ● | ● | ● | ● | 확장 키 1개 |
| `crypto-multi-accounts` | — | — | — | ● | ● | — | 여러 계정 한 번에 (Keystone·OneKey 앱 연동) |
| `crypto-seed` / `crypto-bip39` | — | ◐ | ● | — | ● | — | 시드 자체 (보안상 신중히) |
| `bytes` | ● | ● | ● | ● | ● | ● | 임의 데이터 |

## 2. 표시 성능 (화면 QR을 상대 카메라가 얼마나 잘 읽는가)

| 요소 | 구현한 곳 | 내용 |
|---|---|---|
| 밀도 설정 | SS, JD, KX, **PP** | PP: 한 QR당 최대 250 / 500 / 1000자, **QR을 보는 중에 바로 바꾸고 점 표시로 현재 단계 표시** |
| 프레임 속도 설정 | **JD** | 약 800 / 450 / 270ms 세 단계. 밀도와 별도로 조절 |
| 신뢰성 우선 기본값 | **JD** | xpub 내보내기는 항상 낮은 밀도 + 느린 속도로 고정 (`qrmode.c`) |
| 프레임 수 최소화 | **CC**, KX | CC: 데이터 크기를 보고 QR 버전 15 / 25 / 40 중에서 프레임 수가 가장 적은 것 선택. KX: `find_min_num_parts` |
| 크게 보기 | **KS**, CC | KS: 일반 294px ↔ 전체 화면 420px 전환. CC Q: 버전 25까지 표시 |
| 밝기 조절 | **SS**, KX, JD | SS: QR 배경 밝기 31~255 단계 조절 + 안내 팁(상대 카메라가 눈부셔 못 읽는 문제 해결) |
| 색 반전 | **CC** | 흑백 반전 토글 (일부 카메라에서 더 잘 읽힘) |

## 3. 백업·보안 관련 QR

| 기능 | 구현한 곳 | 내용 |
|---|---|---|
| SeedQR / Compact SeedQR | SS, KX, JD, CC, PP | Standard = 단어 번호 4자리 숫자 모드, Compact = 엔트로피 비트 바이트 모드 |
| 옮겨 그리기 가이드 | **SS**, **KX** | SS: 5×5 블록 확대 + **다시 스캔해서 확인**. KX: 영역(격자) 모드·한 줄씩 모드·확대 |
| QR 이미지 저장 | **KX** | QR을 SD 카드에 PBM / BMP / SVG로 저장 |
| QR 인쇄 | KX | 열전사 프린터 (우리 하드웨어 범위 밖) |
| 암호화된 시드 QR | **KX** (KEF) | AES로 암호화한 니모닉을 QR로 |
| 기기 간 암호화 전송 | **CC** (Key Teleport) | ECDH + AES-CTR, 받는 쪽 공개키를 QR로 → 보내는 쪽이 암호화한 데이터를 QR로, 8자리 숫자 비밀번호를 별도 경로로 전달 |
| 설정 QR | SS | 웹 도구에서 만든 설정을 QR로 불러오기 |
| 임의 데이터 QR | KX (Datum tool) | 텍스트·파일을 QR로 만들고 인코딩 변환 |

## 4. 읽기 성능 (M4 참고)

| 요소 | 구현한 곳 | 내용 |
|---|---|---|
| 디코더 | JD·OK: quirc 계열, **PP: rxing(ZXing의 Rust 이식), TryHarder 옵션** | |
| 반전 QR 재시도 | **PP** | 한 번 실패하면 흑백을 뒤집어 다시 시도 |
| 적응형 이진화 | PP (HybridBinarizer) | 조명이 고르지 않아도 읽음 |
| 형식 자동 판별 | **SS** | PSBT(base64·base43·Specter·UR·BBQr), SeedQR, 니모닉 텍스트, 4글자 니모닉, 설정, xpub, 주소, 메시지 서명 요청, 지갑 디스크립터·설정 파일 |
| 카메라 보조 | KX, SS | 눈부심 방지 모드, 카메라 회전 |
| 진행 표시 | 대부분 | 애니메이션 QR 수신률 표시 |

## 5. Bitpunk에 주는 시사점

1. **형식은 셋 다 필요**: UR(지갑 앱 표준), BBQr(Coldcard·Sparrow, 압축으로 프레임이 가장 적음), Specter `pM/N`(Specter Desktop).
2. **UR 이름은 옛 이름과 새 이름을 모두** 지원(PP 방식). 내보낼 때는 호환성이 가장 넓은 옛 이름을 기본으로.
3. **표시 성능 요소를 한데 모으기**: 프레임 수 최소화(CC) + 실시간 밀도 전환(PP) + 프레임 속도(JD) + 밝기(SS) + 반전(CC) + 전체 화면(KS). 여러 프로젝트에 흩어져 있던 것을 한 화면에서 모두 제공하는 기기는 없음.
4. **800×480 화면은 장점**: 1.3~3인치 화면을 쓰는 레퍼런스보다 큰 QR 버전을 정수 배율로 크게 보여 줄 수 있음.
5. **보안 QR은 단계적으로**: 암호화 시드 QR(KX)·Key Teleport(CC)는 M10·M12에 이미 계획됨. QR 엔진은 그때 그대로 재사용.
