//! Private key import strings (M8).

/// Import problems, in `keys::KeyProblem` order.
pub const KEY_PROBLEMS: usize = 6;

pub struct KeyStrings {
    pub title: &'static str,
    pub methods: [(&'static str, &'static str); 2],
    pub type_title: &'static str,
    pub type_help: &'static str,
    pub scan_title: &'static str,
    pub confirm_title: &'static str,
    pub kind_xprv: &'static str,
    pub kind_wif: &'static str,
    pub can_xprv: &'static str,
    pub can_wif: &'static str,
    pub not_new: [&'static str; 2],
    pub load: &'static str,
    pub cancel: &'static str,
    pub refused: &'static str,
    pub problems: [&'static str; KEY_PROBLEMS],
    pub addresses: &'static str,
    pub not_for_wif: &'static str,
    pub fingerprint: &'static str,
    pub comm_title: &'static str,
    /// Status bar badge in place of "AIR-GAPPED" while a chip answers.
    pub comm_badge: &'static str,
    /// "An Ethernet PHY answered at MDIO address {} (ID {})."
    pub comm_found: &'static str,
    pub comm_lines: [&'static str; 3],
}

pub static EN_KEY: KeyStrings = KeyStrings {
    title: "Import private key",
    methods: [("Scan a QR code", "WIF or xprv"), ("Type it", "keyboard")],
    type_title: "Type the key",
    type_help: "WIF (K..., L..., c...) or an extended key (xprv, tprv, yprv, zprv).",
    scan_title: "Scan private key",
    confirm_title: "Load this key?",
    kind_xprv: "Extended private key (XPRV)",
    kind_wif: "Single private key (WIF)",
    can_xprv: "Used as the root: every feature except the words screens.",
    can_wif: "Its four addresses and signing for them. No xpub, multisig or BIP-85.",
    not_new: [
        "New seeds are made from dice or coins only.",
        "This loads a key that already exists.",
    ],
    load: "Load",
    cancel: "Cancel",
    refused: "Key refused",
    problems: [
        "Not a WIF or extended private key.",
        "A key of another network.",
        "Uncompressed keys are not supported.",
        "Not a valid key (out of range).",
        "All seed slots are in use.",
        "This key is already loaded.",
    ],
    addresses: "Addresses of this key",
    not_for_wif: "Not available for a single key (WIF).",
    fingerprint: "Fingerprint",
    comm_title: "Network chip detected",
    comm_badge: "NETWORK CHIP",
    comm_found: "A PHY answered at MDIO address {} (ID {}).",
    comm_lines: [
        "Seeds cannot be loaded and nothing is signed on this board.",
        "Remove the Ethernet PHY and the RJ45 jack (docs/hardware),",
        "then power the device on again.",
    ],
};

pub static KO_KEY: KeyStrings = KeyStrings {
    title: "개인키 가져오기",
    methods: [("QR 스캔", "WIF 또는 xprv"), ("직접 입력", "키보드")],
    type_title: "키를 입력하세요",
    type_help: "WIF (K..., L..., c...) 또는 확장 키 (xprv, tprv, yprv, zprv).",
    scan_title: "개인키 스캔",
    confirm_title: "이 키를 불러올까요?",
    kind_xprv: "확장 개인키 (XPRV)",
    kind_wif: "단일 개인키 (WIF)",
    can_xprv: "뿌리 키로 씁니다: 단어 화면 말고 모든 기능.",
    can_wif: "이 키의 주소 4개와 그 서명만. xpub·멀티시그·BIP-85 없음.",
    not_new: [
        "새 시드는 주사위·동전으로만 만듭니다.",
        "이것은 이미 있는 키를 불러오는 것입니다.",
    ],
    load: "불러오기",
    cancel: "취소",
    refused: "받지 않는 키",
    problems: [
        "WIF나 확장 개인키가 아닙니다.",
        "다른 네트워크의 키입니다.",
        "비압축 키는 지원하지 않습니다.",
        "올바른 키가 아닙니다 (범위 밖).",
        "시드 슬롯이 모두 차 있습니다.",
        "이미 불러온 키입니다.",
    ],
    addresses: "이 키의 주소",
    not_for_wif: "단일 키(WIF)에는 없는 기능입니다.",
    fingerprint: "지문",
    comm_title: "통신 칩 감지",
    comm_badge: "통신 칩",
    comm_found: "MDIO 주소 {}에서 PHY가 응답했습니다 (ID {}).",
    comm_lines: [
        "이 보드에서는 시드를 불러오거나 서명할 수 없습니다.",
        "이더넷 PHY와 RJ45 단자를 떼어 낸 뒤 (docs/hardware)",
        "다시 전원을 켜세요.",
    ],
};
