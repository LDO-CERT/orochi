from django.db import models


class OSEnum(models.TextChoices):
    LINUX = "Linux"
    WINDOWS = "Windows"
    MAC = "Mac"
    OTHER = "Other"


MAGIC_ARCHIVE_MIMETYPES = [
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar",
    "application/gzip",
    "application/x-tar",
]

TOAST_RESULT_COLORS = {
    0: "blue",
    1: "#FFC300",
    2: "green",
    3: "green",
    4: "orange",
    5: "red",
    6: "black",
}

TOAST_DUMP_COLORS = {
    1: "green",
    2: "green",
    3: "red",
    4: "red",
    5: "orange",
    6: "black",
}

SERVICE_VIRUSTOTAL = 1
SERVICE_MISP = 2
SERVICE_OLLAMA = 3
SERVICE_WEBHOOK = 4
SERVICE_SLACK = 5
SERVICE_EMAIL = 6

SERVICES = (
    (SERVICE_VIRUSTOTAL, "VirusTotal"),
    (SERVICE_MISP, "MISP"),
    (SERVICE_OLLAMA, "Ollama"),
    (SERVICE_WEBHOOK, "Webhook"),
    (SERVICE_SLACK, "Slack"),
    (SERVICE_EMAIL, "Email"),
)

DUMP_STATUS_CREATED = 1
DUMP_STATUS_UNZIPPING = 2
DUMP_STATUS_COMPLETED = 3
DUMP_STATUS_DELETED = 4
DUMP_STATUS_ERROR = 5
DUMP_STATUS_MISSING_SYMBOLS = 6
STATUS = (
    (DUMP_STATUS_CREATED, "Created"),
    (DUMP_STATUS_UNZIPPING, "Unzipping"),
    (DUMP_STATUS_COMPLETED, "Completed"),
    (DUMP_STATUS_DELETED, "Deleted"),
    (DUMP_STATUS_ERROR, "Error"),
    (DUMP_STATUS_MISSING_SYMBOLS, "Missing Symbols"),
)

RESULT_STATUS_NOT_STARTED = 0
RESULT_STATUS_RUNNING = 1
RESULT_STATUS_EMPTY = 2
RESULT_STATUS_SUCCESS = 3
RESULT_STATUS_UNSATISFIED = 4
RESULT_STATUS_ERROR = 5
RESULT_STATUS_DISABLED = 6
RESULT = (
    (RESULT_STATUS_NOT_STARTED, "Not Started"),
    (RESULT_STATUS_RUNNING, "Running"),
    (RESULT_STATUS_EMPTY, "Empty"),
    (RESULT_STATUS_SUCCESS, "Success"),
    (RESULT_STATUS_UNSATISFIED, "Unsatisfied"),
    (RESULT_STATUS_ERROR, "Error"),
    (RESULT_STATUS_DISABLED, "Disabled"),
)

COLOR_PALETTE = [
    (
        "#e6194B",
        "Red",
    ),
    (
        "#3cb44b",
        "Green",
    ),
    (
        "#ffe119",
        "Yellow",
    ),
    (
        "#4363d8",
        "Blue",
    ),
    (
        "#f58231",
        "Orange",
    ),
    (
        "#911eb4",
        "Purple",
    ),
    (
        "#42d4f4",
        "mist",
    ),
    (
        "#f032e6",
        "Magenta",
    ),
    (
        "#bfef45",
        "Lime",
    ),
    (
        "#fabed4",
        "Pink",
    ),
    (
        "#469990",
        "Teal",
    ),
    (
        "#dcbeff",
        "Lavender",
    ),
    (
        "#9A6324",
        "Brown",
    ),
    (
        "#fffac8",
        "Beige",
    ),
    (
        "#800000",
        "Maroon",
    ),
    (
        "#aaffc3",
        "Mint",
    ),
    (
        "#808000",
        "Olive",
    ),
    (
        "#ffd8b1",
        "Apricot",
    ),
    (
        "#000075",
        "Navy",
    ),
    (
        "#a9a9a9",
        "Grey",
    ),
]


class IconEnum(models.TextChoices):
    SS_LEA = "ss-lea", "Alpha"
    SS_LEB = "ss-leb", "Beta"
    SS_2ED = "ss-2ed", "Unlimited"
    SS_3ED = "ss-3ed", "Revised"
    SS_1E = "ss-1e", "Alpha (Online)"
    SS_2E = "ss-2e", "Beta (Online)"
    SS_2U = "ss-2u", "Unlimited (Online)"
    SS_3E = "ss-3e", "Revised (Online)"
    SS_4ED = "ss-4ed", "Fourth Edition"
    SS_PSUM = "ss-psum", "Summer Magic"
    SS_5ED = "ss-5ed", "Fifth Edition"
    SS_6ED = "ss-6ed", "Sixth Edition"
    SS_7ED = "ss-7ed", "Seventh Edition"
    SS_8ED = "ss-8ed", "Eighth Edition"
    SS_9ED = "ss-9ed", "Ninth Edition"
    SS_10E = "ss-10e", "Tenth Edition"
    SS_M10 = "ss-m10", "Magic 2010"
    SS_M11 = "ss-m11", "Magic 2011"
    SS_M12 = "ss-m12", "Magic 2012"
    SS_M13 = "ss-m13", "Magic 2013"
    SS_M14 = "ss-m14", "Magic 2014"
    SS_BCORE = "ss-bcore", "Blank Core Set"
    SS_ORI = "ss-ori", "Magic Origins"
    SS_M19 = "ss-m19", "Magic 2019"
    SS_M20 = "ss-m20", "Magic 2020"
    SS_M21 = "ss-m21", "Core 2021"
    SS_AFR = "ss-afr", "Adventures in the Forgotten Realms"
    SS_FDN = "ss-fdn", "Foundations"
    SS_ARN = "ss-arn", "Arabian Nights"
    SS_ATQ = "ss-atq", "Antiquities"
    SS_LEG = "ss-leg", "Legends"
    SS_DRK = "ss-drk", "The Dark"
    SS_FEM = "ss-fem", "Fallen Empires"
    SS_HML = "ss-hml", "Homelands"
    SS_ICE = "ss-ice", "Ice Age"
    SS_ICE2 = "ss-ice2", "Ice Age (Original)"
    SS_ALL = "ss-all", "Alliances"
    SS_CSP = "ss-csp", "Coldsnap"
    SS_MIR = "ss-mir", "Mirage"
    SS_VIS = "ss-vis", "Visions"
    SS_WTH = "ss-wth", "Weatherlight"
    SS_TMP = "ss-tmp", "Tempest"
    SS_STH = "ss-sth", "Stronghold"
    SS_EXO = "ss-exo", "Exodus"
    SS_USG = "ss-usg", "Urza's Saga"
    SS_ULG = "ss-ulg", "Urza's Legacy"
    SS_UDS = "ss-uds", "Urza's Destiny"
    SS_MMQ = "ss-mmq", "Mercadian Masques"
    SS_NEM = "ss-nem", "Nemesis"
    SS_PCY = "ss-pcy", "Prophecy"
    SS_INV = "ss-inv", "Invasion"
    SS_PLS = "ss-pls", "Planeshift"
    SS_APC = "ss-apc", "Apocalypse"
    SS_ODY = "ss-ody", "Odyssey"
    SS_TOR = "ss-tor", "Torment"
    SS_JUD = "ss-jud", "Judgement"
    SS_ONS = "ss-ons", "Onslaught"
    SS_LGN = "ss-lgn", "Legions"
    SS_SCG = "ss-scg", "Scourge"
    SS_MRD = "ss-mrd", "Mirrodin"
    SS_DST = "ss-dst", "Darksteel"
    SS_5DN = "ss-5dn", "Fifth Dawn"
    SS_CHK = "ss-chk", "Champions of Kamigawa"
    SS_BOK = "ss-bok", "Betrayers of Kamigawa"
    SS_SOK = "ss-sok", "Saviors of Kamigawa"
    SS_RAV = "ss-rav", "Ravnica"
    SS_GPT = "ss-gpt", "Guildpact"
    SS_DIS = "ss-dis", "Dissension"
    SS_TSP = "ss-tsp", "Time Spiral"
    SS_PLC = "ss-plc", "Planar Chaos"
    SS_FUT = "ss-fut", "Future Sight"
    SS_LRW = "ss-lrw", "Lorwyn"
    SS_MOR = "ss-mor", "Morningtide"
    SS_SHM = "ss-shm", "Shadowmoor"
    SS_EVE = "ss-eve", "Eventide"
    SS_ALA = "ss-ala", "Shards of Alara"
    SS_CON = "ss-con", "Conflux"
    SS_ARB = "ss-arb", "Alara Reborn"
    SS_ZEN = "ss-zen", "Zendikar"
    SS_WWK = "ss-wwk", "Worldwake"
    SS_ROE = "ss-roe", "Rise of the Eldrazi"
    SS_SOM = "ss-som", "Scars of Mirrodin"
    SS_MBS = "ss-mbs", "Mirrodin Besieged"
    SS_NPH = "ss-nph", "New Phyrexia"
    SS_ISD = "ss-isd", "Innistrad"
    SS_DKA = "ss-dka", "Dark Ascension"
    SS_AVR = "ss-avr", "Avacyn Restored"
    SS_RTR = "ss-rtr", "Return to Ravnica"
    SS_GTC = "ss-gtc", "Gatecrash"
    SS_DGM = "ss-dgm", "Dragon's Maze"
    SS_THS = "ss-ths", "Theros"
    SS_BNG = "ss-bng", "Born of the Gods"
    SS_JOU = "ss-jou", "Journey into Nyx"
    SS_KTK = "ss-ktk", "Khans of Tarkir"
    SS_FRF = "ss-frf", "Fate Reforged"
    SS_DTK = "ss-dtk", "Unhinged"
    SS_BFZ = "ss-bfz", "Battle for Zendikar"
    SS_OGW = "ss-ogw", "Oath of the Gatewatch"
    SS_SOI = "ss-soi", "Shadows Over Innistrad"
    SS_EMN = "ss-emn", "Eldritch Moon"
    SS_KLD = "ss-kld", "Kaladesh"
    SS_AER = "ss-aer", "Aether Revolt"
    SS_AKH = "ss-akh", "Amonkhet"
    SS_HOU = "ss-hou", "Hour of Devastation"
    SS_XLN = "ss-xln", "Ixalan"
    SS_RIX = "ss-rix", "Rivals of Ixalan"
    SS_DOM = "ss-dom", "Dominaria"
    SS_GRN = "ss-grn", "Guilds of Ravnica"
    SS_RNA = "ss-rna", "Ravnica Allegiance"
    SS_WAR = "ss-war", "War of the Spark"
    SS_ELD = "ss-eld", "Throne of Eldraine"
    SS_THB = "ss-thb", "Theros: Beyond Death"
    SS_IKO = "ss-iko", "Ikoria: Lair of Behemoths"
    SS_ZNR = "ss-znr", "Zendikar Rising"
    SS_KHM = "ss-khm", "Kaldheim"
    SS_STX = "ss-stx", "Strixhaven: School of Mages"
    SS_MID = "ss-mid", "Innistrad: Midnight Hunt"
    SS_VOW = "ss-vow", "Innistrad: Crimson Vow"
    SS_NEO = "ss-neo", "Kamigawa: Neon Dynasty"
    SS_SNC = "ss-snc", "Streets of New Capenna"
    SS_DMU = "ss-dmu", "Dominaria United"
    SS_BRO = "ss-bro", "The Brothers' War"
    SS_ONE = "ss-one", "Phyrexia: All Will Be One"
    SS_MOM = "ss-mom", "March of the Machine"
    SS_MAT = "ss-mat", "March of the Machines: The Aftermath"
    SS_WOE = "ss-woe", "Wilds of Eldraine"
    SS_LCI = "ss-lci", "Lost Caverns of Ixalan"
    SS_MKM = "ss-mkm", "Murders at Karlov Manor"
    SS_OTJ = "ss-otj", "Outlaws of Thunder Junction"
    SS_BIG = "ss-big", "The Big Score"
    SS_BLB = "ss-blb", "Bloomburrow"
    SS_DSK = "ss-dsk", "Duskmourn: House of Horror"
    SS_DFT = "ss-dft", "Aetherdrift"
    SS_TDM = "ss-tdm", "Tarkir: Dragonstorm"
    SS_FIN = "ss-fin", "Final Fantasy"
    SS_EOE = "ss-eoe", "Edge of Eternities"
    SS_SPM = "ss-spm", "Marvel Spider-Man"
    SS_TLA = "ss-tla", "Avatar: The Last Airbender"
    SS_ECL = "ss-ecl", "Lorwyn Eclipsed"
    SS_TMT = "ss-tmt", "Teenage Mutant Ninja Turtles"
    SS_SOS = "ss-sos", "Secrets of Strixhaven"
    SS_MSH = "ss-msh", "Marvel Super Heroes"
    SS_HOB = "ss-hob", "The Hobbit"
    SS_FRA = "ss-fra", "Reality Fracture"
    SS_VAN = "ss-van", "Vanguard"
    SS_HOP = "ss-hop", "Planechase"
    SS_ARC = "ss-arc", "Archenemy"
    SS_CMD = "ss-cmd", "Commander"
    SS_PC2 = "ss-pc2", "Planechase 2012"
    SS_CM1 = "ss-cm1", "Commander's Arsenal"
    SS_C13 = "ss-c13", "Commander 2013"
    SS_CNS = "ss-cns", "Conspiracy"
    SS_C14 = "ss-c14", "Commander 2014"
    SS_C15 = "ss-c15", "Commander 2015"
    SS_CN2 = "ss-cn2", "Conspiracy 2: Take the Crown"
    SS_C16 = "ss-c16", "Commander 2016"
    SS_PCA = "ss-pca", "Planechase Anthology"
    SS_CMA = "ss-cma", "Commander Anthology"
    SS_E01 = "ss-e01", "Archenemy: Nicol Bolas"
    SS_E02 = "ss-e02", "Explorers of Ixalan"
    SS_C17 = "ss-c17", "Commander 2017"
    SS_CM2 = "ss-cm2", "Commander Anthology 2"
    SS_BBD = "ss-bbd", "Battlebond"
    SS_C18 = "ss-c18", "Commander 2018"
    SS_C19 = "ss-c19", "Commander 2019"
    SS_C20 = "ss-c20", "Ikoria: Commander 2020"
    SS_ZNC = "ss-znc", "Zendikar Rising: Commander Decks"
    SS_CC1 = "ss-cc1", "Commander Collection: Green"
    SS_CMR = "ss-cmr", "Commander Legends"
    SS_CMC = "ss-cmc", "Commander Legends Decks"
    SS_KHC = "ss-khc", "Kaldheim Commander"
    SS_C21 = "ss-c21", "Commander 2021"
    SS_AFC = "ss-afc", "Forgotten Realms Commander"
    SS_MIC = "ss-mic", "Innistrad: Midnight Hunt Commander"
    SS_VOC = "ss-voc", "Innistrad: Crimson Vow Commander"
    SS_CC2 = "ss-cc2", "Commander Collection: Black"
    SS_NEC = "ss-nec", "Kamigawa: Neon Dynasty: Commander"
    SS_NCC = "ss-ncc", "Streets of New Capenna: Commander"
    SS_CLB = "ss-clb", "Commander Legends: Battle for Baldur's Gate"
    SS_DMC = "ss-dmc", "Dominaria United Commander"
    SS_40K = "ss-40k", "Warhammer 40K"
    SS_BRC = "ss-brc", "The Brothers' War Commander"
    SS_ONC = "ss-onc", "Phyrexia: All Will Be One Commander"
    SS_MOC = "ss-moc", "March of the Machine Commander"
    SS_SCD = "ss-scd", "Starter Commander Decks"
    SS_CMM = "ss-cmm", "Commander Masters"
    SS_LTC = "ss-ltc", "The Lord of the Rings: Tales of Middle-Earth Commander"
    SS_WHO = "ss-who", "Universes Beyond: Doctor Who"
    SS_WOC = "ss-woc", "Wilds of Eldraine Commander"
    SS_LCC = "ss-lcc", "Lost Caverns of Ixalan Commander"
    SS_PIP = "ss-pip", "Universes Beyond: Fallout"
    SS_MKC = "ss-mkc", "Murders at Karlov Manor Commander"
    SS_OTC = "ss-otc", "Outlaws of Thunder Junction Commander"
    SS_BLC = "ss-blc", "Bloomburrow Commander"
    SS_M3C = "ss-m3c", "Modern Horizons 3 Commander"
    SS_DSC = "ss-dsc", "Duskmourn Commander"
    SS_FDC = "ss-fdc", "Foundations Commander"
    SS_DRC = "ss-drc", "Aetherdrift Commander"
    SS_TDC = "ss-tdc", "Tarkir: Dragonstorm Commander"
    SS_FIC = "ss-fic", "Final Fantasy Commander"
    SS_EOC = "ss-eoc", "Edge of Eternities Commander"
    SS_ECC = "ss-ecc", "Lorwyn Eclipsed Commander"
    SS_TMC = "ss-tmc", "Teenage Mutant Ninja Turtles Eternal-Legal"
    SS_SOC = "ss-soc", "Secrets of Strixhaven Commander"
    SS_HOC = "ss-hoc", "The Hobbit Eternal"
    SS_MSC = "ss-msc", "Marvel Super Heroes Commander"
    SS_CHR = "ss-chr", "Chronicles"
    SS_ATH = "ss-ath", "Anthologies"
    SS_BRB = "ss-brb", "Battle Royale"
    SS_BTD = "ss-btd", "Beatdown"
    SS_DKM = "ss-dkm", "Deckmasters"
    SS_MMA = "ss-mma", "Modern Masters"
    SS_MM2 = "ss-mm2", "Modern Masters 2015"
    SS_EMA = "ss-ema", "Eternal Masters"
    SS_MM3 = "ss-mm3", "Modern Masters 2017"
    SS_REN = "ss-ren", "Renaissance"
    SS_RIN = "ss-rin", "Rinascimento"
    SS_IMA = "ss-ima", "Iconic Masters"
    SS_A25 = "ss-a25", "Masters 25"
    SS_UMA = "ss-uma", "Ultimate Masters"
    SS_MH1 = "ss-mh1", "Modern Horizons"
    SS_2XM = "ss-2xm", "Double Masters"
    SS_JMP = "ss-jmp", "Jumpstart"
    SS_MB1 = "ss-mb1", "Mystery Booster"
    SS_MH2 = "ss-mh2", "Modern Horizons 2"
    SS_STA = "ss-sta", "Strixhaven: Mystical Archives"
    SS_J21 = "ss-j21", "Jumpstart: Historic Horizons"
    SS_2X2 = "ss-2x2", "Double Masters 2022"
    SS_BRR = "ss-brr", "The Brothers' War Retro Artifacts"
    SS_J22 = "ss-j22", "Jumpstart 2022"
    SS_MUL = "ss-mul", "Multiverse Legends"
    SS_WOT = "ss-wot", "Wilds of Eldraine Enchanting Tales"
    SS_BR = "ss-br", "Battle Royale (alternate)"
    SS_SPG = "ss-spg", "Special Guests"
    SS_OTP = "ss-otp", "Breaking News"
    SS_MB2 = "ss-mb2", "Mystery Booster 2"
    SS_J25 = "ss-j25", "Jumpstart 2025"
    SS_PIO = "ss-pio", "Pioneer Masters"
    SS_FCA = "ss-fca", "Final Fantasy: Through the Ages"
    SS_MAR = "ss-mar", "Marvel (TBD)"
    SS_EOS = "ss-eos", "Edge of Eternities: Stellar Sights"
    SS_POR = "ss-por", "Portal"
    SS_P02 = "ss-p02", "Portal 2"
    SS_PTK = "ss-ptk", "Portal Three Kingdoms"
    SS_S99 = "ss-s99", "Starter 1999"
    SS_S00 = "ss-s00", "Starter 2000"
    SS_W16 = "ss-w16", "Welcome Deck 2016"
    SS_W17 = "ss-w17", "Welcome Deck 2017"
    SS_EVG = "ss-evg", "Elves v. Goblins"
    SS_DD2 = "ss-dd2", "Jace v. Chandra"
    SS_DDC = "ss-ddc", "Divine v. Demonic"
    SS_DDD = "ss-ddd", "Garruk v. Liliana"
    SS_DDE = "ss-dde", "Phyrexia v. Coalition"
    SS_DDF = "ss-ddf", "Elspeth v. Tezzeret"
    SS_DDG = "ss-ddg", "Knights v. Dragons"
    SS_DDH = "ss-ddh", "Ajani v. Nicol Bolas"
    SS_DDI = "ss-ddi", "Venser v. Koth"
    SS_DDJ = "ss-ddj", "Izzet v. Golgari"
    SS_DDK = "ss-ddk", "Sorin v. Tibalt"
    SS_DDL = "ss-ddl", "Heroes v. Monsters"
    SS_DDM = "ss-ddm", "Jace v. Vraska"
    SS_DDN = "ss-ddn", "Speed v. Cunning"
    SS_DDO = "ss-ddo", "Kiora v. Elspeth"
    SS_DDP = "ss-ddp", "Zendikar v. Eldrazi"
    SS_DDQ = "ss-ddq", "Zendikar v. Eldrazi"
    SS_DDR = "ss-ddr", "Nissa v. Ob Nixilis"
    SS_TD2 = "ss-td2", "New Phyrexia v. Mirrodin Pure"
    SS_DDS = "ss-dds", "Mind v. Might"
    SS_DDT = "ss-ddt", "Merfolk v. Goblins"
    SS_DDU = "ss-ddu", "Elves v. Inventors"
    SS_DRB = "ss-drb", "FTV: Dragons"
    SS_V09 = "ss-v09", "FTV: Exiled"
    SS_V0X = "ss-v0x", "FTV: Vaults"
    SS_V10 = "ss-v10", "FTV: Relics"
    SS_V11 = "ss-v11", "FTV: Legends"
    SS_V12 = "ss-v12", "FTV: Realms"
    SS_V13 = "ss-v13", "FTV: Twenty"
    SS_V14 = "ss-v14", "FTV: Annihilation"
    SS_V15 = "ss-v15", "FTV: Angels"
    SS_V16 = "ss-v16", "FTV: Lore"
    SS_V17 = "ss-v17", "FTV: Transform"
    SS_H09 = "ss-h09", "FTV: Slivers"
    SS_PD2 = "ss-pd2", "FTV: Fire & Lightning"
    SS_PD3 = "ss-pd3", "PDS: Graveborn"
    SS_MD1 = "ss-md1", "Modern Event Deck"
    SS_SS1 = "ss-ss1", "Signature Spellbook: Jace"
    SS_SS2 = "ss-ss2", "Signature Spellbook: Gideon"
    SS_SS3 = "ss-ss3", "Signature Spellbook: Chandra"
    SS_GS1 = "ss-gs1", "Jiang Yanggu & Mu Yanling"
    SS_AZORIUS = "ss-azorius", "Guild Kit: Azorius"
    SS_BOROS = "ss-boros", "Guild Kit: Boros"
    SS_DIMIR = "ss-dimir", "Guild Kit: Dimir"
    SS_GOLGARI = "ss-golgari", "Guild Kit: Golgari"
    SS_GRUUL = "ss-gruul", "Guild Kit: Gruul"
    SS_IZZET = "ss-izzet", "Guild Kit: Izzet"
    SS_ORZHOV = "ss-orzhov", "Guild Kit: Orzhov"
    SS_RAKDOS = "ss-rakdos", "Guild Kit: Rakdos"
    SS_SELESNYA = "ss-selesnya", "Guild Kit: Selesnya"
    SS_SIMIC = "ss-simic", "Guild Kit: Simic"
    SS_GNT = "ss-gnt", "Game Night"
    SS_GK1 = "ss-gk1", "GRN Guild Kits"
    SS_GK2 = "ss-gk2", "RNA Guild Kits"
    SS_GN2 = "ss-gn2", "Game Night 2019"
    SS_TSR = "ss-tsr", "Time Spiral Remastered"
    SS_DMR = "ss-dmr", "Dominaria Remastered"
    SS_GN3 = "ss-gn3", "Game Night: Free for All"
    SS_LTR = "ss-ltr", "The Lord of the Rings: Tales of Middle-Earth"
    SS_RVR = "ss-rvr", "Ravnica Remastered"
    SS_SLD = "ss-sld", "Secret Lair"
    SS_SLD2 = "ss-sld2", "Secret Lair (logo)"
    SS_CLU = "ss-clu", "Ravnica: Clue Edition"
    SS_ACR = "ss-acr", "Universes Beyond: Assassin's Creed"
    SS_MH3 = "ss-mh3", "Modern Horizons 3"
    SS_INR = "ss-inr", "Innistrad Remastered"
    SS_SPE = "ss-spe", "Marvel Spider-Man Eternal-Legal"
    SS_TLE = "ss-tle", "Avatar: the Last Airbender Eternal-Legal"
    SS_PZA = "ss-pza", "Teenage Mutant Ninja Turtle Source Material Cards"
    SS_PGRU = "ss-pgru", "Guru"
    SS_PMTG1 = "ss-pmtg1", "MtG Promo"
    SS_PMTG2 = "ss-pmtg2", "MtG Promo (Alternate)"
    SS_PLEAF = "ss-pleaf", "Leaf Promo"
    SS_PMEI = "ss-pmei", "Media Insert"
    SS_PARL = "ss-parl", "Arena Promo (DCI)"
    SS_DPA = "ss-dpa", "Duels of the Planeswalkers"
    SS_PBOOK = "ss-pbook", "Book Inserts"
    SS_PAST = "ss-past", "Astral"
    SS_PARL2 = "ss-parl2", "Arena League"
    SS_PARL3 = "ss-parl3", "Arena League (MODO)"
    SS_EXP = "ss-exp", "Zendikar Expeditions"
    SS_PSALVAT05 = "ss-psalvat05", "Salvat 2005"
    SS_PSALVAT11 = "ss-psalvat11", "Salvat 2011"
    SS_MP1 = "ss-mp1", "Kaladesh Inventions"
    SS_PXBOX = "ss-pxbox", "Xbox Media Promo"
    SS_PMPS = "ss-pmps", "Magic Premiere Shop"
    SS_PMPU = "ss-pmpu", "Mirrodin Pure"
    SS_MP2 = "ss-mp2", "Amonkhet Invocations"
    SS_PIDW = "ss-pidw", "IDW Promo"
    SS_PDRC = "ss-pdrc", "Dragon*Con Promo"
    SS_PHEART = "ss-pheart", "Phoenix Heart Celebration Card"
    SS_H17 = "ss-h17", "HasCon 2017"
    SS_PDEP = "ss-pdep", "Duelist: Extra Pulled"
    SS_PSEGA = "ss-psega", "SEGA Dreamcast"
    SS_PTSA = "ss-ptsa", "The Sorcerer's Apprentice"
    SS_HTR = "ss-htr", "Heroes of the Realm"
    SS_MED = "ss-med", "Mythic Edition"
    SS_PTG = "ss-ptg", "Ponies: the Galloping"
    SS_J20 = "ss-j20", "Judge Academy 2020"
    SS_ZNE = "ss-zne", "Zendikar Rising Expeditions"
    SS_BOT = "ss-bot", "The Brothers' War Transformers"
    SS_REX = "ss-rex", "Jurassic World"
    SS_STA_JPN = "ss-sta-jpn", "Strixhaven Mystical Archives Japan Promos"
    SS_SOA = "ss-soa", "Secrets of Strixhaven Mystical Archives"
    SS_SOA_JPN = "ss-soa-jpn", "Secrets of Strixhaven Mystical Archives (Japan)"
    SS_ME1 = "ss-me1", "Masters Edition"
    SS_ME2 = "ss-me2", "Masters Edition II"
    SS_ME3 = "ss-me3", "Masters Edition III"
    SS_ME4 = "ss-me4", "Masters Edition IV"
    SS_VMA = "ss-vma", "Vintage Masters"
    SS_TPR = "ss-tpr", "Tempest Remastered"
    SS_PZ1 = "ss-pz1", "Legendary Cube"
    SS_PMODO = "ss-pmodo", "Magic Online"
    SS_XDUELS = "ss-xduels", "Magic Duels"
    SS_XMODS = "ss-xmods", "Magic Online Deck Series"
    SS_PZ2 = "ss-pz2", "Treasure Chests"
    SS_HA1 = "ss-ha1", "Historic Anthology 1"
    SS_AKR = "ss-akr", "Amonkhet Remastered"
    SS_KLR = "ss-klr", "Kaladesh Remastered"
    SS_Y22 = "ss-y22", "Alchemy 2022"
    SS_HBG = "ss-hbg", "Alchemy Horizons: Baldur's Gate"
    SS_YDMU = "ss-ydmu", "Alchemy: Dominaria"
    SS_SIR = "ss-sir", "Shadows Over Innistrad"
    SS_SIS = "ss-sis", "Shadows of the Past"
    SS_EA1 = "ss-ea1", "Explorer Anthology 1"
    SS_Y24 = "ss-y24", "Alchemy 2024"
    SS_Y25 = "ss-y25", "Alchemy 2025"
    SS_PMA = "ss-pma", "Puzzle Masters"
    SS_PM2 = "ss-pm2", "Puzzle Masters 2"
    SS_DVK = "ss-dvk", "Puzzle Masters: Daxos vs. Kalemne"
    SS_OM1 = "ss-om1", "Through the Omenpaths"
    SS_OMB = "ss-omb", "Through the Omenpaths Bonus Sheet"
    SS_Y26 = "ss-y26", "Alchemy 2026"
    SS_UGL = "ss-ugl", "Unglued"
    SS_UNH = "ss-unh", "Unhinged"
    SS_UST = "ss-ust", "Unstable"
    SS_UND = "ss-und", "Unsanctioned"
    SS_UNF = "ss-unf", "Unfinity"
    SS_UNA = "ss-una", "Unfinity Acorns"
    SS_XCLE = "ss-xcle", "Collector's Edition"
    SS_XICE = "ss-xice", "International Collector's Edition"
    SS_X2PS = "ss-x2ps", "Two Player Introductory Set"
    SS_X4EA = "ss-x4ea", "Alternate 4th Edition"
    SS_PAPAC = "ss-papac", "APAC Lands"
    SS_PEURO = "ss-peuro", "Euro Lands"
    SS_PFNM = "ss-pfnm", "Friday Night Magic"
    SS_30A = "ss-30a", "30th Anniversary Edition"


DEFAULT_YARA_PATH = "/yara/default.yara"
