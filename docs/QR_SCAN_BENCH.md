# QR 스캔 성능 시험대 (M3)

휴대폰 카메라가 Bitpunk Signer 화면의 QR을 얼마나 잘 읽는지 **시뮬레이션으로 측정**한다.
실제 앱 화면(상태바·정보 패널 포함)을 그대로 그린 뒤, 카메라가 화면을 찍을 때 생기는
열화를 입히고, 서로 독립된 디코더 2종으로 읽어 원문과 **바이트 단위로 같을 때만** 성공으로 센다.

코드: `crates/bp-app/src/bench.rs` · 재현:

```
cargo test -p bp-app --release scan_bench_full -- --ignored --nocapture   # 전체 표 (약 3분)
cargo test -p bp-app scan_bench_defaults                                  # CI 검사 (기본 화면, 기준 거리)
```

## 1. 방법

| 단계 | 내용 |
|---|---|
| 화면 | 앱의 실제 렌더러로 800×480 프레임버퍼를 그림 (애니메이션은 프레임마다, UR은 fountain 조각 2개 포함) |
| 배율 | 화면 1px당 카메라 픽셀 수. 0.35 / 0.45 / 0.55 / 0.7 / 0.9 |
| 기하 | 무작위 회전(±15°), 원근 기울임(호모그래피, 직선 유지), 위치 흔들림. 2×2 슈퍼샘플링 |
| 광학 | 화면 검정·흰색이 카메라에 찍히는 밝기(대비 감소), 가우시안 흐림, 센서 잡음 |
| 디코더 | `rqrr` (quirc 계열) · `rxing` (ZXing 계열, ZXing의 ALSO_INVERTED처럼 반전 영상도 재시도). 둘 다 테스트 전용. M4부터 **Bitpunk 스캐너**(`bp-qr::scan`) 열 추가 |
| 판정 | 디코딩 결과 == 그 프레임의 원문. "phone (either)"은 rqrr·rxing 중 하나라도 성공한 비율로, 휴대폰 지갑 앱이 Bitpunk 화면을 읽는 경우를 대신함 (실제 앱은 한 가지 디코더를 씀) |

**기준 거리 = 배율 0.55**: 휴대폰 카메라가 기기를 화면의 70% 정도로 담고, 스캐너가 640×480으로 줄여서 디코딩하는 경우에 해당한다.

| 조건 | 흐림 σ | 잡음 σ | 대비 (검정–흰색) | 회전 | 원근 |
|---|---|---|---|---|---|
| medium (목표 조건) | 1.0px | 8 | 35–215 | ±15° | ±5% |
| hard (스트레스) | 1.5px | 14 | 55–190 | ±15° | ±10% |

**목표 (M3 계획):** 기본 설정 + medium 조건 + 기준 거리에서 95% 이상.

## 2. 결과 요약

| 측정 | 기준 거리 성공률 |
|---|---|
| 첫 측정 (QR 영역 390px, Low = 버전 8 고정 → 6px 모듈) | 83.2% |
| 시험대 버그 수정 (원근 변환이 직선을 휘게 만들던 문제 → 진짜 호모그래피) | 94.3% |
| **QR 영역 428px (안내줄을 옆 패널로) + 밀도를 최소 모듈 크기로 정의** | **98.2% — 목표 달성** |
| hard 조건 (참고) | 37.9% |

### 결정 사항

1. **모듈 크기가 성공률을 결정한다.** 같은 거리에서 버전 8·6px는 85%, 버전 6·8px는 98%, 버전 3·11px는 100%.
   그래서 밀도를 "최대 QR 버전" 대신 **최소 모듈 크기**로 정의했다: Low 8px · Medium 6px · High 5px.
   QR 영역 428px 기준으로 Low는 버전 7까지, Medium은 11까지, High는 15까지 쓴다. 전체 화면(480px)에서는 모듈이 더 커진다.
2. **QR 화면에서 하단 안내줄을 없앴다.** 키 안내는 오른쪽 정보 패널로 옮기고, QR 영역을 390px → 428px로 키웠다.
3. **Auto = Low** (Low로 40프레임 이하일 때). 700바이트 PSBT 크기의 UR은 Low가 10프레임·기준 거리 100%,
   Medium은 4프레임이지만 68%, High는 3프레임·10%. 가까이서 찍으면 Medium이 더 빠를 수 있으므로 ◄►로 바로 바꿀 수 있다.
4. **xpub 내보내기 기본값 Low + 느린 속도 유지** (Jade 정책). crypto-account는 Low에서 2프레임 애니메이션(버전 6·8px)이 된다.
5. **Compact SeedQR(버전 1, 21×21)은 92%로 가장 약하다.** 버전 1에는 정렬 패턴이 없어 원근 기울임에 민감하다.
   크기는 SeedQR 규격(12단어 = 21×21, 옮겨 그리기 템플릿)이라 바꾸지 않는다. 카메라를 화면과 평행하게 들면 된다.
6. **반전**: rqrr는 반전 QR을 읽지 못하고, ZXing 계열(ALSO_INVERTED)은 88%. 반전은 일부 카메라용 선택 기능으로 둔다.
7. **밝기 최저 단계**도 기준 거리 95%. 이 시뮬레이션은 과노출(흰색 번짐)을 모델링하지 않으므로, 밝기를 낮추는 이점은 실제 기기에서 확인한다.
8. **hard 조건**에서는 큰 모듈(Specter 88%, SeedQR Standard 92%)만 버틴다. 어려운 환경에서는 전체 화면(Enter)과 가까운 거리를 안내한다.

### 한계

시뮬레이션이다. 실제 휴대폰·지갑 앱(Sparrow 등)으로 읽는 확인은 M3 완료 기준 체크리스트에서 한다.
예상 수신 시간은 프레임마다 성공이 독립이라는 가정의 대략치다.

## 3. Bitpunk 스캐너 (M4)

M4에서 직접 구현한 QR 스캐너(`bp-qr::scan`, ZXing식 파이프라인 + 버전 정보·타이밍 패턴으로 크기 확정 + 패턴 적합도로 원근 보정)를 같은 영상으로 측정했다.

| 측정 | Bitpunk | rqrr | rxing | 휴대폰 (either) |
|---|---|---|---|---|
| 기본 화면, medium, 기준 거리 | **98.2%** | — | — | 98.2% |
| 기본 화면, hard, 기준 거리 | **56.1%** | — | — | 37.9% |
| 700바이트 UR, Medium 밀도, 기준 거리 | **98%** | 42% | 50% | 68% |
| 반전 QR, 기준 거리 | **100%** | 0% | 88% | 88% |

### 실사진 세트 (ZXing blackbox qrcode-1~6)

실제 카메라로 찍은 QR 사진 179장을 0°·90° 두 방향으로 읽었다 (Apache-2.0 테스트 데이터, 저장소에는 넣지 않음).
재현: `tools/fetch_zxing_qr_photos.sh /tmp/zxing` 후
`ZXING_QR_PHOTOS=/tmp/zxing/core/src/test/resources/blackbox cargo test -p bp-qr --release --test photos -- --ignored --nocapture`

| 세트 | 사진 × 2방향 | Bitpunk | rqrr | rxing |
|---|---|---|---|---|
| qrcode-1 | 40 | **40** | 30 | 33 |
| qrcode-2 | 70 | 62 | 53 | **64** |
| qrcode-3 | 84 | **82** | 67 | 77 |
| qrcode-4 | 96 | **73** | 54 | 71 |
| qrcode-5 | 38 | **38** | 21 | 36 |
| qrcode-6 | 30 | **30** | 18 | 29 |
| **전체** | 358 | **325 (90.8%)** | 243 (67.9%) | 310 (86.6%) |

일본어 사진(Kanji 모드)도 읽도록 ISO 규격의 Kanji 모드를 Shift JIS 바이트로 출력한다 (비트코인 데이터에는 쓰이지 않음).

### 처리 시간 (데스크톱, release)

| 프레임 (640×480) | 시간 |
|---|---|
| QR이 있는 프레임 | 약 1.5 ms |
| 무작위 잡음 (최악의 경우) | 약 6 ms |

실제 칩에서의 시간은 하드웨어 트랙(H)에서 다시 잰다.

## 4. 전체 표

#### Default QR screens, medium conditions

blur 1 px, noise 8, contrast 35-215, rotation up to 15 deg, perspective up to 5%, 40 trials per row

| Screen | QR | scale | Bitpunk | rqrr | rxing | phone (either) |
|---|---|---|---|---|---|---|
| xpub UR crypto-account | v6 8px | 0.35 | 50% | 8% | 35% | **40%** |
| xpub UR crypto-account | v6 8px | 0.45 | 100% | 90% | 90% | **100%** |
| xpub UR crypto-account | v6 8px | 0.55 | 100% | 90% | 92% | **98%** |
| xpub UR crypto-account | v6 8px | 0.7 | 100% | 100% | 72% | **100%** |
| xpub UR crypto-account | v6 8px | 0.9 | 100% | 100% | 82% | **100%** |
| xpub UR crypto-output | v6 8px | 0.35 | 48% | 0% | 25% | **25%** |
| xpub UR crypto-output | v6 8px | 0.45 | 100% | 68% | 88% | **95%** |
| xpub UR crypto-output | v6 8px | 0.55 | 100% | 82% | 92% | **98%** |
| xpub UR crypto-output | v6 8px | 0.7 | 100% | 95% | 72% | **100%** |
| xpub UR crypto-output | v6 8px | 0.9 | 100% | 100% | 82% | **100%** |
| xpub text [fp/path]zpub | v6 8px | 0.35 | 28% | 5% | 18% | **20%** |
| xpub text [fp/path]zpub | v6 8px | 0.45 | 98% | 70% | 90% | **92%** |
| xpub text [fp/path]zpub | v6 8px | 0.55 | 100% | 90% | 90% | **100%** |
| xpub text [fp/path]zpub | v6 8px | 0.7 | 100% | 100% | 72% | **100%** |
| xpub text [fp/path]zpub | v6 8px | 0.9 | 100% | 100% | 82% | **100%** |
| xpub Specter pM/N | v3 11px | 0.35 | 90% | 80% | 90% | **98%** |
| xpub Specter pM/N | v3 11px | 0.45 | 98% | 95% | 95% | **100%** |
| xpub Specter pM/N | v3 11px | 0.55 | 98% | 98% | 90% | **100%** |
| xpub Specter pM/N | v3 11px | 0.7 | 100% | 98% | 70% | **100%** |
| xpub Specter pM/N | v3 11px | 0.9 | 98% | 100% | 88% | **100%** |
| address (Taproot, upper-case) | v4 8px | 0.35 | 48% | 0% | 38% | **38%** |
| address (Taproot, upper-case) | v4 8px | 0.45 | 100% | 88% | 95% | **98%** |
| address (Taproot, upper-case) | v4 8px | 0.55 | 100% | 98% | 90% | **100%** |
| address (Taproot, upper-case) | v4 8px | 0.7 | 100% | 98% | 68% | **100%** |
| address (Taproot, upper-case) | v4 8px | 0.9 | 100% | 100% | 85% | **100%** |
| SeedQR Standard | v2 12px | 0.35 | 100% | 95% | 95% | **100%** |
| SeedQR Standard | v2 12px | 0.45 | 100% | 100% | 100% | **100%** |
| SeedQR Standard | v2 12px | 0.55 | 100% | 100% | 90% | **100%** |
| SeedQR Standard | v2 12px | 0.7 | 100% | 100% | 78% | **100%** |
| SeedQR Standard | v2 12px | 0.9 | 100% | 100% | 80% | **100%** |
| SeedQR Compact | v1 14px | 0.35 | 70% | 35% | 58% | **78%** |
| SeedQR Compact | v1 14px | 0.45 | 82% | 68% | 72% | **88%** |
| SeedQR Compact | v1 14px | 0.55 | 90% | 80% | 68% | **92%** |
| SeedQR Compact | v1 14px | 0.7 | 98% | 88% | 55% | **95%** |
| SeedQR Compact | v1 14px | 0.9 | 95% | 98% | 65% | **100%** |

기준 거리(0.55)에서: 휴대폰 **98.2%** (275/280), Bitpunk 스캐너 **98.2%** (275/280)

#### Default QR screens, hard conditions

blur 1.5 px, noise 14, contrast 55-190, rotation up to 15 deg, perspective up to 10%, 40 trials per row

| Screen | QR | scale | Bitpunk | rqrr | rxing | phone (either) |
|---|---|---|---|---|---|---|
| xpub UR crypto-account | v6 8px | 0.35 | 0% | 0% | 0% | **0%** |
| xpub UR crypto-account | v6 8px | 0.45 | 0% | 0% | 0% | **0%** |
| xpub UR crypto-account | v6 8px | 0.55 | 25% | 2% | 5% | **8%** |
| xpub UR crypto-account | v6 8px | 0.7 | 92% | 52% | 50% | **80%** |
| xpub UR crypto-account | v6 8px | 0.9 | 90% | 78% | 55% | **88%** |
| xpub UR crypto-output | v6 8px | 0.35 | 0% | 0% | 0% | **0%** |
| xpub UR crypto-output | v6 8px | 0.45 | 0% | 0% | 0% | **0%** |
| xpub UR crypto-output | v6 8px | 0.55 | 40% | 2% | 2% | **5%** |
| xpub UR crypto-output | v6 8px | 0.7 | 95% | 32% | 55% | **72%** |
| xpub UR crypto-output | v6 8px | 0.9 | 90% | 70% | 55% | **88%** |
| xpub text [fp/path]zpub | v6 8px | 0.35 | 0% | 0% | 0% | **0%** |
| xpub text [fp/path]zpub | v6 8px | 0.45 | 0% | 0% | 0% | **0%** |
| xpub text [fp/path]zpub | v6 8px | 0.55 | 45% | 5% | 8% | **12%** |
| xpub text [fp/path]zpub | v6 8px | 0.7 | 92% | 50% | 58% | **75%** |
| xpub text [fp/path]zpub | v6 8px | 0.9 | 85% | 75% | 45% | **90%** |
| xpub Specter pM/N | v3 11px | 0.35 | 0% | 2% | 0% | **2%** |
| xpub Specter pM/N | v3 11px | 0.45 | 78% | 40% | 40% | **65%** |
| xpub Specter pM/N | v3 11px | 0.55 | 92% | 70% | 68% | **88%** |
| xpub Specter pM/N | v3 11px | 0.7 | 78% | 85% | 58% | **90%** |
| xpub Specter pM/N | v3 11px | 0.9 | 72% | 100% | 50% | **100%** |
| address (Taproot, upper-case) | v4 8px | 0.35 | 0% | 0% | 0% | **0%** |
| address (Taproot, upper-case) | v4 8px | 0.45 | 0% | 0% | 0% | **0%** |
| address (Taproot, upper-case) | v4 8px | 0.55 | 48% | 0% | 0% | **0%** |
| address (Taproot, upper-case) | v4 8px | 0.7 | 98% | 45% | 60% | **75%** |
| address (Taproot, upper-case) | v4 8px | 0.9 | 75% | 82% | 60% | **95%** |
| SeedQR Standard | v2 12px | 0.35 | 0% | 0% | 0% | **0%** |
| SeedQR Standard | v2 12px | 0.45 | 78% | 62% | 52% | **85%** |
| SeedQR Standard | v2 12px | 0.55 | 92% | 88% | 75% | **92%** |
| SeedQR Standard | v2 12px | 0.7 | 82% | 95% | 62% | **100%** |
| SeedQR Standard | v2 12px | 0.9 | 88% | 98% | 55% | **100%** |
| SeedQR Compact | v1 14px | 0.35 | 0% | 10% | 0% | **10%** |
| SeedQR Compact | v1 14px | 0.45 | 38% | 22% | 18% | **35%** |
| SeedQR Compact | v1 14px | 0.55 | 50% | 45% | 22% | **60%** |
| SeedQR Compact | v1 14px | 0.7 | 72% | 60% | 20% | **68%** |
| SeedQR Compact | v1 14px | 0.9 | 5% | 78% | 0% | **78%** |

기준 거리(0.55)에서: 휴대폰 **37.9%** (106/280), Bitpunk 스캐너 **56.1%** (157/280)

#### Viewer options, medium conditions

| Screen | QR | scale | Bitpunk | rqrr | rxing | phone (either) |
|---|---|---|---|---|---|---|
| crypto-account, full screen | v6 9px | 0.35 | 90% | 32% | 62% | **80%** |
| crypto-account, full screen | v6 9px | 0.45 | 100% | 95% | 92% | **100%** |
| crypto-account, full screen | v6 9px | 0.55 | 100% | 100% | 90% | **100%** |
| crypto-account, full screen | v6 9px | 0.7 | 100% | 100% | 80% | **100%** |
| crypto-account, full screen | v6 9px | 0.9 | 100% | 100% | 90% | **100%** |
| crypto-account, brightness level 3 of 5 | v6 8px | 0.35 | 20% | 2% | 15% | **18%** |
| crypto-account, brightness level 3 of 5 | v6 8px | 0.45 | 98% | 82% | 88% | **98%** |
| crypto-account, brightness level 3 of 5 | v6 8px | 0.55 | 100% | 92% | 92% | **98%** |
| crypto-account, brightness level 3 of 5 | v6 8px | 0.7 | 100% | 100% | 72% | **100%** |
| crypto-account, brightness level 3 of 5 | v6 8px | 0.9 | 100% | 100% | 82% | **100%** |
| crypto-account, brightness level 5 of 5 (dimmest) | v6 8px | 0.35 | 0% | 0% | 0% | **0%** |
| crypto-account, brightness level 5 of 5 (dimmest) | v6 8px | 0.45 | 78% | 32% | 48% | **60%** |
| crypto-account, brightness level 5 of 5 (dimmest) | v6 8px | 0.55 | 90% | 80% | 65% | **95%** |
| crypto-account, brightness level 5 of 5 (dimmest) | v6 8px | 0.7 | 98% | 98% | 70% | **100%** |
| crypto-account, brightness level 5 of 5 (dimmest) | v6 8px | 0.9 | 90% | 100% | 75% | **100%** |
| crypto-account, inverted (rqrr reads no inverted codes) | v6 8px | 0.35 | 0% | 0% | 0% | **0%** |
| crypto-account, inverted (rqrr reads no inverted codes) | v6 8px | 0.45 | 98% | 0% | 22% | **22%** |
| crypto-account, inverted (rqrr reads no inverted codes) | v6 8px | 0.55 | 100% | 0% | 88% | **88%** |
| crypto-account, inverted (rqrr reads no inverted codes) | v6 8px | 0.7 | 100% | 0% | 80% | **80%** |
| crypto-account, inverted (rqrr reads no inverted codes) | v6 8px | 0.9 | 100% | 0% | 75% | **75%** |

#### Density (animated UR), medium conditions

| Payload | QR | frames | scale | Bitpunk | rqrr | rxing | phone (either) | est. time at Normal |
|---|---|---|---|---|---|---|---|---|
| 700 B, Auto | v6 8px | 10 | 0.35 | 50% | 0% | 28% | **28%** | 18.0 s |
| 700 B, Auto | v6 8px | 10 | 0.45 | 100% | 62% | 85% | **92%** | 5.4 s |
| 700 B, Auto | v6 8px | 10 | 0.55 | 100% | 92% | 95% | **100%** | 4.9 s |
| 700 B, Auto | v6 8px | 10 | 0.7 | 100% | 95% | 90% | **100%** | 4.9 s |
| 700 B, Auto | v6 8px | 10 | 0.9 | 100% | 100% | 75% | **100%** | 4.9 s |
| 700 B, Low | v6 8px | 10 | 0.35 | 50% | 0% | 28% | **28%** | 18.0 s |
| 700 B, Low | v6 8px | 10 | 0.45 | 100% | 62% | 85% | **92%** | 5.4 s |
| 700 B, Low | v6 8px | 10 | 0.55 | 100% | 92% | 95% | **100%** | 4.9 s |
| 700 B, Low | v6 8px | 10 | 0.7 | 100% | 95% | 90% | **100%** | 4.9 s |
| 700 B, Low | v6 8px | 10 | 0.9 | 100% | 100% | 75% | **100%** | 4.9 s |
| 700 B, Medium | v11 6px | 4 | 0.35 | 0% | 0% | 0% | **0%** | - |
| 700 B, Medium | v11 6px | 4 | 0.45 | 45% | 0% | 5% | **5%** | 39.6 s |
| 700 B, Medium | v11 6px | 4 | 0.55 | 98% | 42% | 50% | **68%** | 2.9 s |
| 700 B, Medium | v11 6px | 4 | 0.7 | 100% | 65% | 65% | **90%** | 2.2 s |
| 700 B, Medium | v11 6px | 4 | 0.9 | 100% | 90% | 50% | **95%** | 2.1 s |
| 700 B, High | v12 5px | 3 | 0.35 | 0% | 0% | 0% | **0%** | - |
| 700 B, High | v12 5px | 3 | 0.45 | 0% | 0% | 0% | **0%** | - |
| 700 B, High | v12 5px | 3 | 0.55 | 38% | 0% | 10% | **10%** | 14.8 s |
| 700 B, High | v12 5px | 3 | 0.7 | 98% | 18% | 48% | **60%** | 2.5 s |
| 700 B, High | v12 5px | 3 | 0.9 | 100% | 55% | 52% | **82%** | 1.8 s |
| 1000 B, Auto | v7 8px | 14 | 0.35 | 45% | 5% | 28% | **28%** | 25.2 s |
| 1000 B, Auto | v7 8px | 14 | 0.45 | 100% | 72% | 82% | **98%** | 7.1 s |
| 1000 B, Auto | v7 8px | 14 | 0.55 | 100% | 82% | 98% | **100%** | 6.9 s |
| 1000 B, Auto | v7 8px | 14 | 0.7 | 100% | 92% | 90% | **100%** | 6.9 s |
| 1000 B, Auto | v7 8px | 14 | 0.9 | 100% | 95% | 75% | **98%** | 7.1 s |
| 1000 B, Low | v7 8px | 14 | 0.35 | 45% | 5% | 28% | **28%** | 25.2 s |
| 1000 B, Low | v7 8px | 14 | 0.45 | 100% | 72% | 82% | **98%** | 7.1 s |
| 1000 B, Low | v7 8px | 14 | 0.55 | 100% | 82% | 95% | **100%** | 6.9 s |
| 1000 B, Low | v7 8px | 14 | 0.7 | 100% | 92% | 90% | **100%** | 6.9 s |
| 1000 B, Low | v7 8px | 14 | 0.9 | 100% | 95% | 75% | **98%** | 7.1 s |
| 1000 B, Medium | v10 6px | 6 | 0.35 | 0% | 0% | 0% | **0%** | - |
| 1000 B, Medium | v10 6px | 6 | 0.45 | 38% | 0% | 8% | **8%** | 39.6 s |
| 1000 B, Medium | v10 6px | 6 | 0.55 | 95% | 40% | 48% | **65%** | 4.6 s |
| 1000 B, Medium | v10 6px | 6 | 0.7 | 100% | 70% | 70% | **95%** | 3.1 s |
| 1000 B, Medium | v10 6px | 6 | 0.9 | 100% | 92% | 62% | **98%** | 3.0 s |
| 1000 B, High | v15 5px | 3 | 0.35 | 0% | 0% | 0% | **0%** | - |
| 1000 B, High | v15 5px | 3 | 0.45 | 0% | 0% | 0% | **0%** | - |
| 1000 B, High | v15 5px | 3 | 0.55 | 32% | 0% | 8% | **8%** | 19.8 s |
| 1000 B, High | v15 5px | 3 | 0.7 | 100% | 15% | 35% | **42%** | 3.5 s |
| 1000 B, High | v15 5px | 3 | 0.9 | 100% | 40% | 30% | **52%** | 2.8 s |
