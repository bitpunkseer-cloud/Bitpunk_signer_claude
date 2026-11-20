# 레퍼런스 프로젝트 (Reference Projects)

Bitpunk Signer 개발 시 참고할 오픈소스 하드웨어 지갑 / 서명 장치 프로젝트 목록입니다.
링크와 메타데이터는 2026-11-20 기준 GitHub에서 확인했습니다.

> **원칙:** 이 프로젝트들은 *설계·프로토콜·UX·보안 모델* 을 참고하기 위한 자료입니다.
> Bitpunk Signer는 **Rust 기반**으로, `embit`·`libwally-core` 등 기존 라이브러리에 의존하지 않는
> **독자적인 코드와 라이브러리**로 구현합니다. 레퍼런스 코드를 복사하지 말고, 동작 검증
> (테스트 벡터 비교, 상호운용성 테스트) 용도로 활용합니다. 라이선스는 각 저장소에서 반드시 확인하세요
> (`NOASSERTION`은 GitHub가 표준 라이선스로 자동 판별하지 못했다는 의미이며, Coldcard·Krux 등은
> 상업적 이용 제한 조항이 있을 수 있습니다).

## 요약 표

| 프로젝트 | 메인 저장소 | 주 언어 | 라이선스(GitHub 표기) |
|---|---|---|---|
| SeedSigner | https://github.com/SeedSigner/seedsigner | Python | MIT |
| Krux | https://github.com/selfcustody/krux | Python (MicroPython) | 별도 확인 필요 |
| Specter DIY | https://github.com/cryptoadvance/specter-diy | Python (MicroPython) | MIT |
| Jade (DIY 포함) | https://github.com/Blockstream/Jade | C (ESP-IDF) | MIT |
| Coldcard | https://github.com/Coldcard/firmware | Python (MicroPython) + C | 별도 확인 필요 |
| Passport Prime | https://github.com/Foundation-Devices/KeyOS | **Rust** | 별도 확인 필요 |
| Keystone 3 Pro | https://github.com/KeystoneHQ/keystone3-firmware | C + **Rust** | 별도 확인 필요 |
| OneKey Pro 2 | https://github.com/OneKeyHQ/firmware-pro | C (+ MicroPython) | 별도 확인 필요 |

## 프로젝트별 상세

### 1. SeedSigner
- 펌웨어: https://github.com/SeedSigner/seedsigner
- OS 이미지: https://github.com/SeedSigner/seedsigner-os
- 특징: Raspberry Pi Zero 기반, 완전 에어갭, 상태 비저장(stateless), QR 기반 PSBT 서명, SeedQR.
- 참고 포인트: Stateless 설계, SeedQR 포맷, 카메라 기반 엔트로피, UX 흐름.

### 2. Krux
- 펌웨어: https://github.com/selfcustody/krux
- 특징: Kendryte K210 (M5StickV, Maix Amigo, Yahboom 등) 기반, MicroPython, QR 서명.
- 참고 포인트: 저가 RISC-V 보드 지원, 암호화된 니모닉 저장, 다양한 보드 포팅 구조.

### 3. Specter DIY
- 펌웨어: https://github.com/cryptoadvance/specter-diy
- 특징: STM32F469 Discovery 보드 기반, MicroPython, QR 통신, 멀티시그 친화적.
- 참고 포인트: 보안 부트로더, 멀티시그 지갑 관리, 디스크립터 처리.

### 4. Jade (Jade DIY)
- 펌웨어: https://github.com/Blockstream/Jade
- 특징: ESP32 기반, C (ESP-IDF). 공식 하드웨어 외에 M5Stack·TTGO T-Display 등 DIY 보드 빌드 지원.
- 참고 포인트: Blind Oracle 기반 가상 시큐어 엘리먼트(PIN 서버), QR/USB/BLE 통신, CBOR RPC.

### 5. Coldcard
- 펌웨어: https://github.com/Coldcard/firmware
- USB 프로토콜/CLI: https://github.com/Coldcard/ckcc-protocol
- 특징: STM32 + 시큐어 엘리먼트, MicroPython + C, 에어갭(MicroSD/NFC/QR).
- 참고 포인트: PSBT 처리의 엄격함, 듀얼 SE 설계, 시뮬레이터, 다양한 고급 보안 기능(Duress PIN, Trick PIN 등).

### 6. Passport Prime (Foundation)
- OS/펌웨어 (KeyOS): https://github.com/Foundation-Devices/KeyOS
- KeyOS용 Rust std 포크: https://github.com/Foundation-Devices/rust-keyos
- 하드웨어 설계 파일: https://github.com/Foundation-Devices/Passport-Prime-Hardware
- BLE 펌웨어 (nRF52805): https://github.com/Foundation-Devices/prime-ble-firmware
- (이전 세대 Passport v2 펌웨어: https://github.com/Foundation-Devices/passport2)
- 특징: **Rust 기반 마이크로커널 OS(KeyOS)**, QuantumLink(BLE) 통신, 앱 구조.
- 참고 포인트: Rust 임베디드 아키텍처, 프로세스 격리, 하드웨어 오픈소스 설계. Rust로 개발하는 본 프로젝트에 가장 직접적인 참고 대상.

### 7. Keystone 3 Pro
- 펌웨어: https://github.com/KeystoneHQ/keystone3-firmware
- Rust SDK: https://github.com/KeystoneHQ/keystone-sdk-rust
- 특징: 에어갭 QR(UR 표준), 3개 시큐어 엘리먼트, 펌웨어 내부에 Rust 모듈(체인별 파싱/서명) 포함.
- 참고 포인트: C ↔ Rust FFI 구조, UR(Uniform Resources) 인코딩, 멀티체인 트랜잭션 파서.

### 8. OneKey Pro 2
- 펌웨어 (Pro 계열): https://github.com/OneKeyHQ/firmware-pro
- BLE 펌웨어: https://github.com/OneKeyHQ/bluetooth-firmware-pro
- 특징: Trezor 펌웨어 계열 기반, 터치스크린, 지문 인식, 에어갭 QR/BLE/USB.
- ⚠️ 2026-11-20 기준, **"Pro 2" 전용 공개 저장소는 확인되지 않았습니다.** 현재 Pro 계열 공개 펌웨어는
  `firmware-pro`이며, Pro 2 소스가 별도로 공개되면 이 항목을 갱신해야 합니다.

## 개발 시 활용 방법 (제안)

1. **표준 사양 우선:** BIP-32/39/44/84/86, BIP-174/370(PSBT), BIP-380~386(Descriptors),
   BCR UR 표준 등 원문 사양을 기준으로 독자 구현합니다.
2. **테스트 벡터 교차 검증:** BIP 공식 테스트 벡터 + 레퍼런스 장치 출력과 결과를 비교합니다.
3. **상호운용성:** Sparrow, Nunchuk, Specter Desktop 등 코디네이터와 PSBT/QR 호환성을 확인합니다.
4. **보안 모델 비교:** Stateless(SeedSigner) vs 시큐어 엘리먼트(Coldcard/Keystone) vs 가상 SE(Jade) 중
   Bitpunk Signer의 위협 모델을 결정합니다.
