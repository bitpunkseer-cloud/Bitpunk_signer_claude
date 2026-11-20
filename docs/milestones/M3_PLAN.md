# M3 구현 계획 — QR 출력

상태: **승인 대기**

## 1. 목표

기기 화면에 **xpub·주소·SeedQR을 QR로 표시**한다.
**Sparrow가 시뮬레이터 화면의 QR을 카메라로 읽어 관찰 전용 지갑을 만들고, 주소가 기기와 같으면** 완료.

## 2. 범위

| 포함 | 제외 (다른 마일스톤) |
|---|---|
| QR 인코더 직접 구현 (버전 1~40, 오류 정정 L/M/Q/H, 숫자·영숫자·바이트 모드, 마스크 자동 선택) | QR **읽기**(카메라) → M4 |
| BC-UR 인코딩: bytewords, CBOR, 다중 파트 fountain 인코더 | UR 디코딩 → M4 |
| UR 타입: `crypto-hdkey`, `crypto-keypath`, `crypto-account`, `crypto-output` | `crypto-psbt` → M5 |
| xpub QR: 애니메이션 UR `crypto-account`(기본) + 정적 `[지문/경로]xpub` 텍스트 | Specter 레거시 형식, BBQr → M6 |
| 주소 QR | SeedQR 스캔으로 백업 확인 → M4 |
| SeedQR · Compact SeedQR 내보내기 + 손으로 옮겨 그리기 가이드 | |
| QR 밀도 설정 연결(기존 Low/Medium/High), 애니메이션 속도 | |

## 3. QR 인코더 (`bp-qr`)

| 항목 | 내용 |
|---|---|
| 규격 | ISO/IEC 18004 (QR Code Model 2) |
| 모드 | 숫자(Standard SeedQR), 영숫자(대문자 UR·대문자 bech32 주소, 더 작은 QR), 바이트(xpub 텍스트, Compact SeedQR) |
| 오류 정정 | Reed–Solomon (GF(256)), 레벨 L/M/Q/H. 기본 L(SeedSigner와 같음), 화면 표시에는 M도 선택 가능 |
| 마스크 | 8개 마스크의 감점 규칙(규격 4가지)을 계산해 가장 낮은 것 선택 |
| 메모리 | 할당 없음. 최대 177×177 모듈 비트맵을 고정 버퍼에 저장 |
| 그리기 | 화면에서 가능한 최대 정수 배율, 여백(quiet zone) 4모듈, 흰 바탕 |

## 4. BC-UR (`bp-qr::ur`)

| 항목 | 규격 |
|---|---|
| bytewords | BCR-2020-012 (minimal 형식, CRC32 포함) |
| UR 문자열 | BCR-2020-005 `ur:<type>/<seq>-<n>/<fragment>`, QR에는 대문자로 넣어 영숫자 모드 사용 |
| fountain 인코더 | 조각 크기는 QR 밀도 설정에 따름. Xoshiro256** 의사 난수로 조각 조합 (규격 그대로, 디코더와 호환되려면 필수) |
| CBOR | 필요한 부분만 직접 구현 (정수, 바이트열, 텍스트, 배열, 맵, 태그) |
| 레지스트리 타입 | `crypto-hdkey`(303), `crypto-keypath`(304), `crypto-output`(308), `crypto-account`(311) — BCR-2020-007/010/015 |

## 5. 화면

```
Seed options
├─ Export xpub ─► 스크립트 ─► [QR 형식: UR 애니메이션 | 정적 텍스트] ─► QR 화면 ─ Tab: 텍스트 상세(현재 화면)
├─ Address explorer ─► … ─► 주소 상세 ─► QR 표시
└─ Backup SeedQR ─► [Standard | Compact] ─► 경고 ─► SeedQR 전체 ─► 옮겨 그리기 가이드(확대 격자)
```

| 화면 | 내용 |
|---|---|
| xpub QR | 화면 왼쪽에 큰 QR(애니메이션이면 자동으로 다음 조각), 오른쪽에 지문·경로·형식·조각 번호. ◄►로 밀도, Tab으로 텍스트 상세 |
| 주소 QR | QR + 4글자씩 끊은 주소 + 경로. bech32 주소는 대문자로 인코딩해 QR을 작게 (BIP-173 권장) |
| SeedQR | 경고 화면을 거친 뒤 표시. Standard: 숫자 모드 / Compact: 바이트 모드. 12단어 21~25칸, 24단어 25~29칸 |
| 옮겨 그리기 가이드 | SeedSigner 방식: QR을 5×5 블록으로 나눠 A1~E5 좌표와 함께 한 블록씩 확대해서 보여 줌. ◄►▲▼로 이동 |

## 6. 테스트 & 검증

| 대상 | 방법 |
|---|---|
| QR 인코더 | (1) 테스트 전용 `qrcode` 크레이트와 같은 버전·레벨·마스크에서 **모듈 행렬이 똑같은지** 대조 (2) 독립 디코더 `rqrr`(테스트 전용)로 우리 QR을 읽어 원문과 같은지 — 무작위 데이터, 모든 모드·레벨·여러 버전 |
| SeedQR | SeedSigner `tests/test_seedqr.py`의 Standard·Compact 벡터 |
| bytewords · UR | BCR-2020-005/012 규격 예제 + 테스트 전용 `ur` 크레이트와 fountain 조각 대조 |
| crypto-account | BCR-2020-015 예제 + "abandon … about" 시드로 만든 값을 디코더로 되읽어 xpub·경로·지문 확인 |
| 실기기 대조 | 휴대폰·Sparrow로 시뮬레이터 화면의 QR을 직접 스캔 |

## 7. 커밋 단위

1. QR 인코더 (Reed–Solomon, 배치, 마스크, 모드) + 대조 테스트
2. SeedQR · Compact SeedQR 인코딩 + SeedSigner 벡터
3. CBOR · bytewords · UR 문자열 · fountain 인코더
4. UR 레지스트리 타입 (`crypto-hdkey/keypath/account/output`)
5. 화면: QR 위젯, xpub QR, 주소 QR, SeedQR + 옮겨 그리기 가이드
6. 시뮬레이터 배포 + 확인 체크리스트

## 8. 완료 기준

`abandon` ×11 + `about` 시드로:
- [ ] Export xpub → Native SegWit → UR 애니메이션: **Sparrow (New Wallet → Airgapped Hardware Wallet → Scan)로 읽으면** 지문 `73c5da0a`, 첫 주소 `bc1qcr8te…`인 지갑이 만들어짐
- [ ] 정적 텍스트 QR을 휴대폰으로 읽으면 `[73c5da0a/84h/0h/0h]zpub6rFR7y…`
- [ ] 주소 QR을 휴대폰으로 읽으면 화면의 주소와 같음
- [ ] Backup SeedQR(Standard)을 휴대폰으로 읽으면 단어 번호 48자리 숫자 (`0000 0000 … 0003`)
- [ ] 옮겨 그리기 가이드에서 블록 이동이 됨
- [ ] CI 전부 통과
