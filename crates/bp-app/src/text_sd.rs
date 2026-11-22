//! microSD strings (M8).

/// Card problems, in `sd::CardProblem` order.
pub const CARD_PROBLEMS: usize = 7;

pub struct SdStrings {
    pub menu: &'static str,
    pub badge: &'static str,
    pub reading: &'static str,
    pub fs: &'static str,
    pub size: &'static str,
    pub cluster: &'static str,
    pub entries: &'static str,
    pub refresh: &'static str,
    pub power_note: &'static str,
    pub removed: &'static str,
    /// Title and two explanation lines per problem.
    pub problems: [[&'static str; 3]; CARD_PROBLEMS],
}

pub static EN_SD: SdStrings = SdStrings {
    menu: "SD card",
    badge: "SD",
    reading: "Reading the card...",
    fs: "File system",
    size: "Size",
    cluster: "Cluster",
    entries: "Root entries",
    refresh: "Read again",
    power_note: "The card is powered only during each operation: you can remove it at any time.",
    removed: "Card removed",
    problems: [
        ["No card", "Insert a microSD card.", ""],
        [
            "Card not readable",
            "Reading failed. Re-insert the card",
            "and try again.",
        ],
        [
            "No file system",
            "Blank or unknown card.",
            "Format it on this device.",
        ],
        [
            "exFAT card",
            "exFAT is not supported. Format the card as",
            "FAT32 on this device (erases everything on it).",
        ],
        [
            "GPT card",
            "Only MBR cards are supported.",
            "Format the card on this device.",
        ],
        [
            "Unsupported file system",
            "Use FAT16 or FAT32.",
            "Format the card on this device.",
        ],
        [
            "Damaged file system",
            "The card's structures are inconsistent.",
            "Check it on a computer, or format it here.",
        ],
    ],
};

pub static KO_SD: SdStrings = SdStrings {
    menu: "SD 카드",
    badge: "SD",
    reading: "카드를 읽는 중...",
    fs: "파일시스템",
    size: "용량",
    cluster: "클러스터",
    entries: "루트 항목",
    refresh: "다시 읽기",
    power_note: "카드는 작업하는 동안에만 켜집니다. 언제든 빼도 됩니다.",
    removed: "카드가 빠졌습니다",
    problems: [
        ["카드 없음", "microSD 카드를 넣으세요.", ""],
        [
            "카드를 읽지 못함",
            "읽기에 실패했습니다. 카드를 다시 넣고",
            "다시 시도하세요.",
        ],
        [
            "파일시스템 없음",
            "비어 있거나 알 수 없는 카드입니다.",
            "이 기기에서 포맷하세요.",
        ],
        [
            "exFAT 카드",
            "exFAT은 지원하지 않습니다. 이 기기에서 FAT32로",
            "포맷하세요 (카드의 모든 내용이 지워집니다).",
        ],
        ["GPT 카드", "MBR 카드만 지원합니다.", "이 기기에서 포맷하세요."],
        [
            "지원하지 않는 파일시스템",
            "FAT16 또는 FAT32를 쓰세요.",
            "이 기기에서 포맷하세요.",
        ],
        [
            "손상된 파일시스템",
            "카드의 구조가 서로 맞지 않습니다.",
            "컴퓨터에서 검사하거나 여기서 포맷하세요.",
        ],
    ],
};
