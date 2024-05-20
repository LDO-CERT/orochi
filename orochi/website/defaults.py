from django.db import models


class OSEnum(models.TextChoices):
    LINUX = "Linux"
    WINDOWS = "Windows"
    MAC = "Mac"
    OTHER = "Other"


TOAST_RESULT_COLORS = {
    0: "blue",
    1: "yellow",
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
}

SERVICE_VIRUSTOTAL = 1
SERVICE_MISP = 2
SERVICE_MAXMIND = 3
SERVICES = (
    (SERVICE_VIRUSTOTAL, "VirusTotal"),
    (SERVICE_MISP, "MISP"),
    (SERVICE_MAXMIND, "MAXMIND"),
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


class IconEnum(models.TextChoices):
    SS_ORI = "ss-ori", "Magic Origins"
    SS_AFR = "ss-afr", "Adventures in the Forgotten Realms"
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
    SS_DTK = "ss-dtk", "Dragons of Tarkir"
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
    SS_IKO = "ss-iko", "koria: Lair of Behemoths"
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
    SS_MAT = "ss-mat", "March of the Machine: The Aftermath"
    SS_WOE = "ss-woe", "Wilds of Eldraine"
    SS_LCI = "ss-lci", "Lost Caverns of Ixalan"
    SS_MKM = "ss-mkm", "Murders at Karlov Manor"
    SS_OTJ = "ss-otj", "Outlaws of Thunder Junction"
    SS_BIG = "ss-big", "The Big Score"
    SS_BLB = "ss-blb", "Bloomburrow"


DEFAULT_YARA_PATH = "/yara/default.yara"
