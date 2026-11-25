# 기능 대장 (M1~M8) — M9 기능 보존 기준

M9(UX/UI 개선)는 이 대장의 기능을 **하나도 빠뜨리거나 다르게 동작하게 해서는 안 된다**. 바뀌는 것은 모양·위치·조작뿐이며, 바뀌는 위치는 M9-4에서 "M9 이후 위치" 열에 채운다.
새 마일스톤이 기능을 더하면 이 대장에 줄을 더한다(로드맵 "빌드마다 하는 일" 5).

## 0. 보존 장치 (M9-0)

| 장치 | 위치 | 무엇을 보장하나 |
|---|---|---|
| 기능 이름으로 이동 | `crates/bp-app/src/nav.rs` | 시험이 키 번호가 아니라 기능으로 이동한다. 메뉴 경로는 메뉴 표를 탐색해 자동으로 찾으므로 메뉴를 재편해도 시험은 그대로 |
| 도달성 | `nav::tests::every_feature_is_reachable` | 아래 메뉴 기능 25개 모두 주 메뉴에서 실제 키로 닿는다 |
| 화면 전수 | `coverage.rs` + `every_screen_and_step_is_drawn` | 화면 50종 + 흐름 단계 = 139개 상태를 모두 그린다. 새 화면은 목록에 넣지 않으면 컴파일되지 않는다 |
| 출력 기준 | `crates/bp-app/golden/m8-outputs.txt` + `outputs_match_the_m8_baseline` | 모든 출력 404줄이 M8과 바이트 단위로 같다 |
| 로직 동결 | `tools/check_freeze.sh` (CI) | `bp-crypto`·`bp-bitcoin`·`bp-qr`·`bp-fat`·`bp-hal` 소스가 M8 마지막 커밋과 같다 |
| 시뮬레이터 E2E | `sim/e2e/smoke.js` (CI) | 브라우저에서 시드 불러오기 → PSBT 서명 결과가 기준과 같음, microSD 복사·목록·내려받기·제거, 부팅 점검, 페이지 오류 없음 |
| 자원 예산 | `resource_budget` | `App` ≤ 560 KB(M8 끝 485 KB), 글꼴 ≤ 1 MB(M8 끝 417 KB) |

**장치가 실제로 막는지 확인:** 기준 파일의 글자 하나를 바꾸면 `outputs_match_the_m8_baseline`이, 도구 메뉴에서 BIP-85 줄을 빼면 `every_feature_is_reachable`이 실패함을 확인했다.

**M9-0에서 이 장치들이 이미 찾아낸 것**
- SD 화면 순회의 "텍스트 보기" 장면이 실제로는 지갑 가져오기를 실행하고 있었다 (시험 버그) → 보기로 고침.
- 화면 순회의 SeedQR 확인(ScanVerify) 장면이 M8에서 주 메뉴에 SD 카드가 들어가며 SD 메뉴를 열고 있었다 → 의도대로 고침.
- 어떤 시험도 그리지 않던 상태 9개(스캔 대기 5종, BIP-85 QR·시드 고르기, 메시지 서명 실패, 통신 칩 잠금)를 순회에 넣었다.

## 1. 의도한 변경 목록 (M9)

이 목록에 있는 것만 동작이 바뀐다. 각각 전용 시험을 둔다. 목록에 없는 동작 변화는 회귀다.

| # | 변경 | 단위 | 상태 |
|---|---|---|---|
| C1 | 주 메뉴·하위 메뉴 재편(위치·번호) — 아래 "M9 이후 위치" | M9-4 | 완료 — every_feature_is_reachable, 기존 시험은 기능 이름으로 이동해 그대로 통과 |
| C2 | 미구현 기능 줄을 메뉴에서 빼고 설정 > 기기 정보 > 예정 기능으로 | M9-4 | 완료 (자리 표시 화면 삭제) |
| C3 | 첫 실행 안내: 시작 화면 뒤 원칙 3줄 + 언어·네트워크 선택 (저장이 없으니 켤 때마다) | M9-4 | 완료 — splash_times_out_to_the_first_run_screen_then_main, first_run_screen_sets_language_and_network |
| C4 | 세션 로그: 주 메뉴 아래 최근 4건(켠 뒤 경과 시간, 종류, 시드는 지문만), RAM만·전원 끄면 지움 | M9-4 | 완료 — session_log_records_what_happened_and_power_off_wipes_it |
| C5 | 되돌릴 수 없는 동작의 단어 입력 확인: 카드 포맷 `FORMAT`, 시드 지우기 `WIPE` | M9-3 | 완료 — format_asks_twice, discarding_a_seed_needs_the_word_wipe |
| C6 | 화면 보호: 1분(설정 5분·끔) 입력 없으면 비가 화면을 덮음. 깨우는 키는 다른 동작 없음, 단어·SeedQR·BIP-85 결과는 닫힘, 입력 중인 흐름은 그대로. 비밀 아닌 QR 표시·카메라·SD 작업·부팅·잠금 중에는 안 켜짐 | M9-5 | 완료 — screen_saver_closes_secret_screens_and_keeps_typing_flows, screen_saver_waits_for_qr_scanning_and_can_be_turned_off |
| C7 | 부팅 자가 점검 화면: 실제로 하는 검사만(통신 칩 MDIO, 펌웨어 빌드 종류, SD, 시드 없음, 시뮬레이터 경고) | M9-5 | 완료 (화면 순회 boot) |
| C8 | 오류 코드 표시 (`E-영역-번호`, [목록](ERROR_CODES.md)) | M9-3 | 완료 — error_codes_are_documented, refusal_screens_show_their_error_code |
| C9 | 화면 효과·비(설정 3단계) | M9-2 | 효과·설정 완료(설정 > 화면 효과, 기기 전용), 비는 M9-5에서 사용 |
| C10 | 금액 표시 방식: BTC 소수부를 `0.01 234 567`로 띄어 쓰기, 검토 머리말에 다른 단위 금액을 함께 | M9-6 | 완료 — amounts_group_the_sats_in_btc |
| C11 | 화면별 도움말: `?`(호스트 F1)로 열고 아무 키로 닫음(닫는 키는 다른 일을 하지 않음). 글자 입력 화면에서는 `?`가 글자. 단어 입력 화면에서 `?`는 "일치 없음" 대신 도움말 | M9-9 | 완료 — help_opens_with_question_mark_and_the_next_key_only_closes_it, help_topics_fit_in_both_languages |

### M10 의도한 변경 (보안 저장, [M10_PLAN](milestones/M10_PLAN.md))

보관함을 켜지 않으면 기기는 M9와 똑같이 동작한다(기능 대장·골든 출력·과제 효율 시험이 그대로 통과해야 함). 아래만 바뀐다.

| # | 변경 | 단위 | 상태 |
|---|---|---|---|
| D1 | 보관함이 있으면 부팅 뒤 잠금 화면(앞부분 → 단어 2개 → 뒷부분), "보관함 없이 사용" 선택 가능 | M10-4 | 완료 — set_a_pin_then_unlock_after_power_on, esc_on_the_lock_screen_is_a_session_without_the_vault |
| D2 | 메뉴 추가: 시드·키 > 시드 보관함, 설정 > 보안(PIN·속임수 PIN·탬퍼 점검 코드·보관함 지우기) | M10-4~7 | 완료 — 설정 > 보안(PIN·지금 잠그기·보관함 지우기) M10-4, 시드·키 > 시드 보관함 M10-5, 설정 > 보안 > 속임수 PIN M10-6, 탬퍼 점검(잠금 화면 Tab·설정 > 보안) M10-7 |
| D3 | 첫 실행 화면 문구: "M10 전까지 저장 없음" → 보관함 안내 | M10-4 | 완료 — (화면 순회) |

### M11 의도한 변경 (고급 백업·도구, [M11_PLAN](milestones/M11_PLAN.md))

새 기능을 쓰지 않으면 기기는 M10과 똑같이 동작한다. 아래만 바뀐다.

| # | 변경 | 단위 | 상태 |
|---|---|---|---|
| E1 | 주 메뉴에 **[6] 백업·도구**(암호화 백업·보안 노트·OTP·데이터 보기), 설정 [6]→[7]·전원 [7]→[8] | M11-6 | 예정 |
| E2 | 시드·키 메뉴 줄 추가: 새 시드 > SLIP-39 새 지갑, 시드 불러오기 > SLIP-39 조각·Seed XOR 조각·금속판 격자, 시드 옵션 > Seed XOR 나누기·금속판 형식(SLIP-39 슬롯은 SLIP-39 조각) | M11-2~4 | 예정 |
| E3 | 단어 입력을 마치면(체크섬이 맞아도) 전체 단어 검토 화면을 한 번 보임 — 과제 효율에 Enter 1회 늘어남 | M11-5 | 예정 |
| E4 | 보관함 본문의 새 레코드(SLIP-39 시드·노트·OTP·백업 암호). M10 보관함은 그대로 열림 | M11-2·6·7·8 | 예정 |
| E5 | 부팅 점검의 펌웨어 줄 "(M12)" → "(M13)" (로드맵 v4 번호) | M11-0 | 완료 |

흐름 안의 선택지 순서(확인 대화상자, 퀴즈 답, 내보내기 형식 목록, 지갑 단계, BIP-85 앱 목록 등)는 시험이 아직 위치로 고른다(남은 숫자 키 87회). M9에서 이런 목록의 순서를 바꾸는 단위는 먼저 `nav.rs`에 그 목록의 이름 기반 도우미를 더하고, 시험은 그것만 쓰게 한 뒤 바꾼다.

## 1-1. M9 이후 위치 (M9-4 메뉴 재편)

주 메뉴: **[1] 서명하기 · [2] 받기·확인 · [3] 시드·키 · [4] 멀티시그 지갑 · [5] SD 카드 · [6] 설정 · [7] 전원**. QR 스캔은 메뉴 어디서나 Fn+Q.
흐름을 마치거나 Esc로 나오면 그 기능이 있는 메뉴로 돌아간다(스캔·메시지 서명 → 서명하기; M8에서는 주 메뉴였다).

| M8 위치 | M9 이후 |
|---|---|
| 주 메뉴 > 스캔 | 서명하기 > QR 스캔 |
| 도구 > 메시지 서명 | 서명하기 > 메시지 서명 |
| 도구 > 주소 탐색 · 주소 확인 · 서명 확인 | 받기·확인 > 주소 탐색 · 주소 확인 · 서명 확인 |
| 시드 > (불러온 시드) · 새 시드 · 불러오기 · 개인키 가져오기 | 시드·키 > 같은 항목 |
| 도구 > BIP-85 | 시드·키 > BIP-85 자식 시드 |
| 도구 > 마지막 단어 계산 | 시드·키 > 새 시드 만들기 > 마지막 단어 계산 |
| 도구 > 멀티시그 지갑 | 주 메뉴 > 멀티시그 지갑 |
| 주 메뉴 > SD 카드 · 설정 · 전원 | 그대로 (번호 5 · 6 · 7) |
| 미구현 줄(M10 시드 보관함, M11 SLIP-39·Tinyseed·Seed XOR·암호화 백업·보안 메모·TOTP) | 설정 > 기기 정보 > 예정 기능 |

## 2. 기능 목록

열: 번호 · 기능 · 지금 위치(M8) · 덮는 시험 · M9 이후 위치(M9-4에서 채움)

### 시드 만들기 (M1, M6)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-001 | 주사위(D6) 12/24단어 | 시드 > 새 시드 > 주사위 | dice_flow_creates_seed_only_after_full_quiz, enter_is_blocked_until_checks_pass |
| F-002 | 동전 12/24단어 | 시드 > 새 시드 > 동전 | alternating_coins_cannot_create_a_seed |
| F-003 | D20 (숫자 입력 후 Space) | 시드 > 새 시드 > D20 | d20_rolls_are_typed_then_recorded_with_space |
| F-004 | 엔트로피 검사(최소 횟수·분포·연속·자기상관), 통과 전 Enter 잠김 | 엔트로피 입력 | patterned_dice_cannot_create_a_seed, enter_is_blocked_until_checks_pass |
| F-005 | Del 되돌리기, 입력 중 Esc는 확인 후 폐기 | 엔트로피 입력 | escape_from_entry_asks_before_wiping |
| F-006 | 단어 표시 + 경고, 받아쓰기 퀴즈를 통과해야 생성 | 생성 흐름 | dice_flow_creates_seed_only_after_full_quiz |
| F-007 | 퀴즈 실패 → 다시 보기·재시험·폐기 | 생성 흐름 | one_wrong_answer_fails_the_quiz_and_creates_nothing, discard_after_failed_quiz_wipes_flow |
| F-008 | 마지막 단어 계산(뽑은 단어 + 동전) | 도구 > 마지막 단어 | final_word_from_drawn_words_and_coins, final_word_matches_bip39_for_random_flips, backspace_on_empty_coins_returns_to_words |

### 시드 불러오기 (M1, M4)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-010 | 단어 입력(4글자 자동 완성, 3글자 단어는 Enter, 전체·접두 모두) | 시드 > 불러오기 > 단어 입력 | typed_words_load_with_autocomplete, full_words_and_prefixes_both_work, three_letter_word_needs_enter |
| F-011 | 체크섬 오류 → 단어 고치기 | 단어 입력 | checksum_error_lets_user_fix_a_word |
| F-012 | 단어 번호 입력 | 시드 > 불러오기 > 단어 번호 | word_numbers_entry |
| F-013 | SeedQR 스캔(표준·Compact) → 불러오기·버리기, 시드가 아니면 거부 | 시드 > 불러오기 > SeedQR / 주 메뉴 스캔 | scan_seedqr_from_camera_and_load_it, scan_seed_discard_and_not_a_seed |
| F-014 | 슬롯 3개, 가득 차면 안내 | 공통 | (화면 순회 SlotsFull) |
| F-015 | 시드 메뉴는 지문만 표시(단어 없음) | 시드 | seeds_menu_shows_fingerprint_not_words |

### 시드 옵션·xpub·주소 (M2, M3)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-020 | 단어 보기 | 시드 옵션 | m2_screens_render |
| F-021 | 패스프레이즈 입력·검토(새 지문)·적용·수정·취소 | 시드 옵션 | passphrase_review_shows_new_fingerprint_and_applies, passphrase_edit_and_cancel_keep_old_wallet |
| F-022 | 시드 버리기(확인) — 그 시드의 지갑도 지움 | 시드 옵션 | discarding_the_seed_forgets_its_wallets |
| F-023 | SeedQR 백업(표준·Compact) + 경고 + 옮겨 적기 격자 | 시드 옵션 | seedqr_backup_and_transcribe |
| F-024 | 옮겨 적은 SeedQR 확인(스캔 비교) | 옮겨 적기 > v | verify_copied_seedqr |
| F-025 | 스크립트 선택(기본 2종, 고급 설정 4종) | xpub·주소 | script_types_follow_advanced_setting |
| F-026 | xpub 보기(계정 바꾸기) + QR 4형식(UR account·UR output·원점 포함 텍스트·Specter) | 시드 옵션 > xpub | xpub_qr_formats, xpub_and_explorer_navigation, loaded_seed_matches_bip84_and_bip86_vectors |
| F-027 | QR 표시 조작(밀도·속도·전체 화면·계정 숫자) | QR 화면 | qr_display_controls |
| F-028 | 주소 탐색(받기·거스름, 페이지, 상세·QR) | 시드 옵션 / 도구 > 주소 탐색 | xpub_and_explorer_navigation, tools_explorer_needs_a_seed |
| F-029 | 테스트넷 접두어 | 설정 > 네트워크 | testnet_setting_changes_prefixes |

### 스캔 (M4)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-030 | 무엇이든 스캔(주소·xpub·디스크립터·UR·바이너리·텍스트 자동 판별) | 주 메뉴 > 스캔 | scan_screens_render, scanned_address_shows_and_state_is_wiped |
| F-031 | 애니메이션 UR·BBQr·Specter 진행 표시 | 스캔 | animated_psbt_over_ur_text_frames |
| F-032 | Fn+Q는 메뉴에서만 스캐너를 연다 | 공통 | qr_key_opens_scanner_from_menus_only, scan_opens_from_menu_and_qr_key |

### PSBT 서명 (M5)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-040 | 검토(개요·출력·수수료·승인)·취소·서명 | 스캔 → 검토 | review_then_cancel_or_sign, back_navigation |
| F-041 | 경고는 하나씩 확인 | 검토 | warnings_are_confirmed_one_by_one |
| F-042 | 공격은 검토를 끝냄(위조 등) | 검토 | attacks_end_the_review |
| F-043 | 확인 안 된 금액은 명시적 동의 | 검토 | unverified_amounts_need_an_explicit_override |
| F-044 | 서명한 금액은 전원을 끌 때까지 기억 | 검토 | signed_amounts_are_remembered_until_power_off |
| F-045 | 다른 시드면 필요한·찾은 지문 표시 | 검토 | wrong_seed_shows_need_and_found |
| F-046 | 서명 결과 QR 3형식(UR·BBQr·Specter), 완료 시 지움 | 서명 결과 | signed_psbt_qr_round_trips_in_every_format |
| F-047 | 수수료 설정이 검토를 바꿈 | 설정 > 수수료 | fee_settings_change_the_review |

### 주소 검증·메시지 (M6)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-050 | 주소 검증(받기·거스름, 번호 힌트, 1,000개 단위 멈춤·더·다른 계정, 다른 네트워크·스크립트 거부) | 도구 > 주소 검증 / 주 메뉴 스캔 | verify_finds_receive_and_change_addresses, verify_uses_the_index_hint_and_the_last_index, verify_pauses_after_a_batch_and_offers_more_or_another_account, verify_refuses_other_networks_scripts_and_non_addresses |
| F-051 | 메시지 서명 기본 꺼짐(설정에서만 켬) | 설정 > 메시지 서명 | message_signing_is_off_until_the_device_turns_it_on |
| F-052 | signmessage QR — p2wpkh·p2sh·p2pkh(Electrum/BIP-137)·Taproot(BIP-322 simple) | 스캔 | signmessage_qr_signs_every_address_type |
| F-053 | 직접 입력한 메시지 + 탐색기 주소 | 도구 > 메시지 서명 | typed_message_with_an_address_from_the_explorer |
| F-054 | 긴 메시지는 쪽마다 읽어야 함 | 메시지 | long_messages_must_be_read_page_by_page |
| F-055 | 잘못된 요청은 이유와 함께 거부 | 메시지 | bad_requests_are_refused_with_the_reason |
| F-056 | BIP-322 PSBT 메시지 서명·거부, 보유 증명 | 스캔 → 검토 | bip322_psbts_sign_messages_for_both_address_types, bip322_psbts_are_refused_when_off_forged_or_against_the_rules, proof_of_reserves_needs_every_input_to_be_ours |
| F-057 | 서명 검증(armored 스캔, 단계별 입력) → "내 주소인가" | 도구 > 서명 검증 / 스캔 | armored_messages_verify_from_the_main_scanner, verify_signature_step_by_step_then_check_the_address |

### 설정·전원 (M1, M6)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-060 | 네트워크·단위·QR 밀도·고급·언어·메시지 서명·수수료 경고/차단/기준·SD 원본 지우기 | 설정 | network_setting_cycles, language_setting_switches_every_string, fee_settings_change_the_review |
| F-061 | 설정 QR 내보내기·가져오기(약화 금지) | 설정 > 설정 QR / 스캔 | settings_qr_exports_and_imports_without_weakening |
| F-062 | 정보 화면 | 설정 > 정보 | (화면 순회 About) |
| F-063 | 전원 끄기 = 시드·흐름·기억 모두 지움 | 전원 | power_off_wipes_seeds |
| F-064 | 한국어·영어 전 화면 | 설정 > 언어 | every_screen_fits_in_every_language, every_issue_text_fits |
| F-065 | 시작 화면 시간 초과 → 주 메뉴, TEST ONLY 표시 | 부팅 | splash_times_out_to_the_first_run_screen_then_main |

### 멀티시그 (M7)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-070 | 지갑 가져오기(디스크립터·Coldcard·JSON·UR) + 공동서명자 확인 후 등록 | 도구 > 멀티시그 / 스캔 | register_by_checking_every_cosigner, main_menu_scan_opens_wallet_import |
| F-071 | 지갑 코드로 등록(이전 세션), 바뀐 지갑은 다른 코드 | 멀티시그 | register_with_code_from_earlier_session, a_changed_wallet_gets_another_code |
| F-072 | 거부 사유 표시 | 멀티시그 | refusals_name_the_reason |
| F-073 | 감시 전용 지갑(서명 안 함) | 멀티시그 | verify_only_wallet, verify_only_review_never_signs |
| F-074 | 지갑 내보내기 4형식 | 지갑 > 내보내기 | export_round_trips |
| F-075 | 지갑 메뉴(주소·공동서명자·내보내기·지우기), 4개 한도 | 지갑 | wallet_menu_keys_and_remove, registry_full |
| F-076 | 에어갭 생성(크기·공동서명자 스캔·확인·거부) | 멀티시그 > 만들기 | create_wallet_air_gapped, create_size_choices, create_refuses_bad_cosigners |
| F-077 | 내 멀티시그 키 내보내기 3형식 | 멀티시그 | export_my_multisig_key |
| F-078 | 멀티시그 지출 검토·서명, 공동서명자 먼저 서명 | 스캔 → 검토 | registered_multisig_spend_is_reviewed_and_signed, cosigner_signed_first_then_complete |
| F-079 | 미등록 지출 → 전역 xpub으로 재구성 + 코드 | 스캔 → 검토 | unregistered_spend_registers_by_code, unregistered_spend_without_xpubs_cannot_be_signed |
| F-080 | 지갑 주소 보기, 멀티시그 주소 검증 | 지갑 / 스캔 | wallet_addresses_view, multisig_address_is_verified |
| F-081 | 시드 없으면 지갑 없음 | 멀티시그 | no_seed_no_wallets |

### microSD (M8)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-090 | 카드 상태·문제 설명·다시 읽기, 넣고 뺌 감지, 상태 표시줄 SD | 주 메뉴 > SD 카드 | probes_a_formatted_card, explains_unusable_cards, removal_and_insertion_are_noticed, badge_follows_the_card |
| F-091 | 파일 탐색(숨김 감춤, 페이지, 깊이 4), 카드가 바뀌면 열린 파일 닫기 | SD > 파일 보기 | browses_folders_and_hides_dot_files, long_folders_come_in_pages, card_changes_close_open_files |
| F-092 | 내용으로 종류 판별, 텍스트 보기(닫으면 지움), 지우기(확인) | 파일 | tells_file_kinds_from_content, text_view_is_wiped_on_close, delete_asks_then_removes |
| F-093 | 카드 포맷(확인 2단계) | SD > 카드 포맷 | format_asks_twice |
| F-094 | PSBT 목록 → 서명 → 전체 PSBT 저장(이름 규칙·번호), 큰·깨진 파일 거부 | SD > PSBT 서명 | signs_psbt_files_and_saves_the_full_psbt, refuses_large_and_broken_psbt_files, psbt_file_helpers |
| F-095 | 원본 지우기 설정, 뽑힌 카드에 다시 저장 | 설정 / 저장 | wipes_the_original_when_asked, a_pulled_card_can_be_saved_to_again |
| F-096 | 메시지 파일 → .sig | 파일 > 메시지 서명 | signs_message_files_and_saves_the_signature |
| F-097 | QR 내보내기를 S로 파일 저장(xpub JSON·ccxp·지갑·설정) | QR 화면 | qr_exports_save_as_files |
| F-098 | 지갑 파일 가져오기(.bpw 태그 자동 등록), 바꿔치기 거부 | 파일 | wallet_files_round_trip_and_tags_register, tampered_wallet_files_do_not_register |
| F-099 | 설정 파일(약화 금지), 시드 단어 파일은 불러오지 않음 | 파일 | settings_files_never_weaken, seed_words_in_a_file_are_never_loaded |
| F-100 | 손상 카드·파일 퍼징 | — | fuzz_damaged_cards_through_the_app, fuzz_file_decoders |

### BIP-85 · 개인키 · 기기 (M8)
| # | 기능 | M8 위치 | 시험 |
|---|---|---|---|
| F-110 | BIP-85 6종(12/18/24단어·WIF·XPRV·HEX·BASE64·BASE85), 번호·길이 | 도구 > BIP-85 | child_keys_match_embit, lengths_stay_in_range |
| F-111 | 결과 QR(SeedQR·Compact), SD에는 저장 안 함 | BIP-85 결과 | qr_shows_the_secret_but_never_saves_it |
| F-112 | 자식 시드를 빈 슬롯에 불러오기, 시드 필요 | BIP-85 결과 | child_mnemonic_loads_into_a_free_slot, needs_a_seed |
| F-120 | 개인키 가져오기(입력·QR): xprv 계열, WIF | 시드 > 개인키 가져오기 | wif_typed_loads_a_single_key_slot, xprv_scanned_loads_a_root_slot |
| F-121 | 잘못된 키 거부(형식·네트워크·비압축·범위·가득·중복) | 개인키 | bad_keys_are_refused |
| F-122 | WIF 단일 키 서명, 경로 기능 없음, 주소 4종 | 개인키 슬롯 | a_wif_slot_signs_its_inputs, single_keys_do_not_offer_path_features |
| F-130 | 부팅 통신 칩 탐지 → 지우고 잠금 | 부팅 | a_network_chip_locks_the_device |

### M9에서 더한 것 (M9)
| # | 기능 | 위치 | 시험 |
|---|---|---|---|
| F-150 | 화면 효과 전체·약하게·끔, QR은 효과 밖 | 설정 > 화면 효과 | qr_codes_read_through_screen_effects |
| F-151 | 첫 실행 화면: 원칙, 언어·네트워크 | 부팅 직후 | first_run_screen_sets_language_and_network |
| F-152 | 세션 로그 | 주 메뉴 아래 | session_log_records_what_happened_and_power_off_wipes_it |
| F-153 | 화면 보호 1분·5분·끔, 단어 화면에 가림까지 남은 시간 | 설정 > 화면 보호 | screen_saver_*, words_screen_counts_down_to_the_screen_saver |
| F-154 | 부팅 자가 점검 로그 | 부팅 | (화면 순회) |
| F-155 | 화면별 도움말 `?` | 모든 화면 | help_opens_with_question_mark_and_the_next_key_only_closes_it, help_topics_fit_in_both_languages |
| F-156 | 되돌릴 수 없는 동작의 단어 입력 확인(FORMAT·WIPE) | SD > 카드 포맷, 시드 옵션 > 시드 지우기 | format_asks_twice, discarding_a_seed_needs_the_word_wipe |
| F-157 | 오류 코드 표시 | 거부·실패 화면 | error_codes_are_documented, refusal_screens_show_their_error_code |

### M10에서 더한 것 (M10)
| # | 기능 | 위치 | 시험 |
|---|---|---|---|
| F-160 | PIN 정하기·바꾸기: 앞부분 4~8자 + 뒷부분 4자 이상을 두 번, 확인 단어 2개 | 설정 > 보안 > PIN | set_a_pin_then_unlock_after_power_on, pin_rules_and_mismatch |
| F-161 | 잠금 화면: 앞부분 → 확인 단어 2개 → 뒷부분, 보관함 없이 사용 | 전원 켜기(보관함이 있을 때) | set_a_pin_then_unlock_after_power_on, esc_on_the_lock_screen_is_a_session_without_the_vault, attack_nothing_typed_or_loaded_stays_in_ram, fuzz_random_keys_on_the_vault_screens |
| F-162 | 틀린 PIN: 남은 횟수, 4번째부터 대기 1분·5분·15분·1시간(전원을 꺼도 유지), 10번째에 영구 삭제 | 잠금 화면 | wrong_pins_count_wait_and_erase_on_the_tenth, attack_the_wait_cannot_be_typed_through, attack_restoring_the_flash_does_not_give_attempts_back |
| F-163 | 지금 잠그기, 보관함 지우기(WIPE 입력) | 설정 > 보안 | lock_now_change_pin_and_erase |
| F-164 | 보관함 형식: A/B 쓰기, 롤백 거부, 전원이 끊겨도 온전한 보관함 하나, 다른 기기·변조 거부 | (내부) | a_power_cut_anywhere_leaves_one_whole_vault, a_pin_change_survives_a_power_cut, an_older_flash_image_is_refused, another_chip_or_element_cannot_open_it, any_changed_byte_is_refused_without_panicking, seeds_settings_and_wallets_round_trip, a_passphrase_is_never_stored, full_vault_and_wrong_fingerprint, bad_bodies_are_refused_without_panicking, attack_an_old_flash_copy_opens_nothing_after_a_pin_change, attack_the_flash_in_another_device_opens_nothing, attack_a_changed_trick_area_is_refused_not_obeyed |
| F-165 | 보안 칩·플래시 문제는 오류 코드(E-VLT)와 함께 알리고 보관함 없이 사용 | 잠금 화면 | a_broken_secure_element_is_a_problem_with_a_code |
| F-166 | 시드 보관함: 불러온 시드 넣기(단어·XPRV·WIF, 최대 8개, 패스프레이즈는 넣지 않음), 목록, 슬롯에 불러오기, 빼기(WIPE 입력) | 시드·키 > 시드 보관함 | stored_seeds_come_back_after_power_on, keys_and_passphrase_seeds_keep_their_fingerprint, the_list_loads_removes_and_counts_eight |
| F-167 | 보관함이 열리면 설정을 적용하고 앞의 시드를 빈 슬롯에 불러옴 | 잠금 해제 | stored_seeds_come_back_after_power_on, the_list_loads_removes_and_counts_eight |
| F-168 | 등록한 멀티시그 지갑을 보관, 그 시드가 들어오면 코드 없이 다시 등록(등록 규칙 재검사) | 멀티시그 지갑 | wallets_register_again_for_their_seed, attack_forged_wallet_records_register_nothing |
| F-169 | 설정을 보관(설정 메뉴를 떠날 때), 잠금 화면은 보관함의 언어로 | 설정 | settings_are_kept_and_the_lock_screen_speaks_their_language |
| F-170 | 보관함 저장 실패 알림, 내용이 바뀌면 다시 시도 | 모든 화면 | a_failed_save_is_reported_once_and_retried_on_the_next_change |
| F-171 | 속임수 PIN 미끼 지갑: 불러온 시드의 BIP-85 자식(1001~1003)이 보관함처럼 열림, 아무것도 쓰지 않음, 시도 횟수를 쓰지 않음 | 설정 > 보안 > 속임수 PIN | a_decoy_pin_opens_a_decoy_seed_and_uses_no_attempt, trick_pins_open_before_the_secure_element_and_stay_hidden, attack_a_decoy_looks_like_the_vault |
| F-172 | 속임수 PIN 지운 뒤 'PIN 틀림'·지운 뒤 미끼 지갑: 보관함을 영구히 지우고 잠금 화면이나 미끼로 계속 | 설정 > 보안 > 속임수 PIN | an_erase_trick_erases_then_looks_like_a_wrong_pin, an_erase_then_decoy_trick_opens_the_decoy |
| F-173 | 속임수 PIN 빈 기기처럼 보이기: 아무것도 지우지 않고 보관함 없는 세션 | 설정 > 보안 > 속임수 PIN | a_blank_trick_starts_like_a_device_without_a_vault |
| F-174 | 속임수 PIN 규칙: 보관함 PIN·다른 속임수 PIN과 달라야 함, 3개까지, 지우기 | 설정 > 보안 > 속임수 PIN | trick_pins_must_differ_and_are_three_at_most |
| F-175 | 탬퍼 점검: 점검 코드(6~16자, 저장 안 함) + 펌웨어 SHA-256 + 기기 키 + 보안 칩 → 단어 2개, 펌웨어·기기가 바뀌면 달라짐, 시도 횟수 안 씀 | 잠금 화면 Tab, 설정 > 보안 > 탬퍼 점검 | the_tamper_check_words_change_only_with_the_firmware, tamper_words_follow_the_code_the_firmware_and_the_device |
| F-176 | 탬퍼 점검은 조용히 지운 뒤에도 같은 모습, 펌웨어 해시가 없는 플랫폼에서는 이유를 알림 | 잠금 화면 | the_tamper_check_goes_on_after_a_silent_erase_and_needs_a_firmware_hash |
| F-177 | 메뉴에서 아무것도 하지 않는 줄은 이유를 키 막대 위에 보임 | 모든 메뉴 | a_menu_row_that_does_nothing_says_why |
| F-178 | SE050 드라이버: T=1 over I2C, SCP03(전부 암호화·MAC), SE05x 명령 — 보관함이 그 위에서 동작, 버스에 비밀 평문 없음 ([M10_SE050](M10_SE050.md)) | (내부) | the_vault_runs_on_the_se050_driver, a_power_cut_on_the_se050_leaves_one_whole_vault, nothing_secret_crosses_the_bus_in_the_clear, published_known_answers, commands_match_the_reference_driver, fuzz_garbage_on_the_bus_never_panics, fuzz_responses_apdus_and_frames_never_panic |

### M11에서 더한 것 (M11)

| # | 기능 | 위치 | 시험 |
|---|---|---|---|
| F-180 | SLIP-39 엔진: 조각 읽기·쓰기(RS1024), 두 단계 Shamir(GF(256), 상수 시간 곱셈), 패스프레이즈 Feistel 암호, 조각을 하나씩 받으며 검사(다른 묶음·같은 번호·다이제스트), 비밀·패스프레이즈·구성·주사위에서 유도한 값으로 새 묶음 — 공식 벡터 45개 전부, 참조 구현과 바이트 단위로 같음 | (내부, `bp-backup`) | published_vectors, published_invalid_vectors_fail_for_the_right_reason, splits_match_the_reference_byte_for_byte, any_enough_shares_recover_the_reference_secret, shares_are_checked_as_they_come, a_wrong_share_empties_its_group_to_be_typed_again, the_same_choices_make_the_same_set_and_others_an_unrelated_one, fuzz_words_and_share_sequences_never_panic |

### 시뮬레이터 (M3~M8)
| # | 기능 | 시험 |
|---|---|---|
| F-140 | 카메라: 이미지·웹캠·텍스트 붙여넣기, 서명 결과 상자 | sim/e2e/smoke.js (붙여넣기·서명 결과) |
| F-141 | microSD 패널: 넣기/빼기·복사·끌어다 놓기·목록·내려받기·지우기·비우기 | sim/e2e/smoke.js (복사·목록·내려받기·빼기) |
| F-142 | 부팅 점검 버튼 | sim/e2e/smoke.js |
| F-143 | 화면 위 CardKB(Sym·Shift·Fn) | sim/e2e/smoke.js (Fn+Q) |
| F-144 | 보관함 패널: SE050 드라이버 + 모의 칩(M10-8), 페이지 메모리에만(새로고침하면 새 기기), 상태 표시 | sim/e2e/smoke.js (PIN 정하기·잠금 화면·열기) |
