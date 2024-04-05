OPERATING_SYSTEM = (
    ("Linux", "Linux"),
    ("Windows", "Windows"),
    ("Mac", "Mac"),
    ("Other", "Other"),
)

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
ICONS = (
    ("ss-arn", "Arabian Nights"),
    ("ss-atq", "Antiquities"),
    ("ss-leg", "Legends"),
    ("ss-drk", "The Dark"),
    ("ss-fem", "Fallen Empires"),
    ("ss-hml", "Homelands"),
    ("ss-ice", "Ice Age"),
    ("ss-ice2", "Ice Age (Original)"),
    ("ss-all", "Alliances"),
    ("ss-csp", "Coldsnap"),
    ("ss-mir", "Mirage"),
    ("ss-vis", "Visions"),
    ("ss-wth", "Weatherlight"),
    ("ss-tmp", "Tempest"),
    ("ss-sth", "Stronghold"),
    ("ss-exo", "Exodus"),
    ("ss-usg", "Urza's Saga"),
    ("ss-ulg", "Urza's Legacy"),
    ("ss-uds", "Urza's Destiny"),
    ("ss-mmq", "Mercadian Masques"),
    ("ss-nem", "Nemesis"),
    ("ss-pcy", "Prophecy"),
    ("ss-inv", "Invasion"),
    ("ss-pls", "Planeshift"),
    ("ss-apc", "Apocalypse"),
    ("ss-ody", "Odyssey"),
    ("ss-tor", "Torment"),
    ("ss-jud", "Judgement"),
    ("ss-ons", "Onslaught"),
    ("ss-lgn", "Legions"),
    ("ss-scg", "Scourge"),
    ("ss-mrd", "Mirrodin"),
    ("ss-dst", "Darksteel"),
    ("ss-5dn", "Fifth Dawn"),
    ("ss-chk", "Champions of Kamigawa"),
    ("ss-bok", "Betrayers of Kamigawa"),
    ("ss-sok", "Saviors of Kamigawa"),
    ("ss-rav", "Ravnica"),
    ("ss-gpt", "Guildpact"),
    ("ss-dis", "Dissension"),
    ("ss-tsp", "Time Spiral"),
    ("ss-plc", "Planar Chaos"),
    ("ss-fut", "Future Sight"),
    ("ss-lrw", "Lorwyn"),
    ("ss-mor", "Morningtide"),
    ("ss-shm", "Shadowmoor"),
    ("ss-eve", "Eventide"),
    ("ss-ala", "Shards of Alara"),
    ("ss-con", "Conflux"),
    ("ss-arb", "Alara Reborn"),
    ("ss-zen", "Zendikar"),
    ("ss-wwk", "Worldwake"),
    ("ss-roe", "Rise of the Eldrazi"),
    ("ss-som", "Scars of Mirrodin"),
    ("ss-mbs", "Mirrodin Besieged"),
    ("ss-nph", "New Phyrexia"),
    ("ss-isd", "Innistrad"),
    ("ss-dka", "Dark Ascension"),
    ("ss-avr", "Avacyn Restored"),
    ("ss-rtr", "Return to Ravnica"),
    ("ss-gtc", "Gatecrash"),
    ("ss-dgm", "Dragon's Maze"),
    ("ss-ths", "Theros"),
    ("ss-bng", "Born of the Gods"),
    ("ss-jou", "Journey into Nyx"),
    ("ss-ktk", "Khans of Tarkir"),
    ("ss-frf", "Fate Reforged"),
    ("ss-dtk", "Dragons of Tarkir"),
    ("ss-bfz", "Battle for Zendikar"),
    ("ss-ogw", "Oath of the Gatewatch"),
    ("ss-soi", "Shadows Over Innistrad"),
    ("ss-emn", "Eldritch Moon"),
    ("ss-kld", "Kaladesh"),
    ("ss-aer", "Aether Revolt"),
    ("ss-akh", "Amonkhet"),
    ("ss-hou", "Hour of Devastation"),
    ("ss-xln", "Ixalan"),
    ("ss-rix", "Rivals of Ixalan"),
    ("ss-dom", "Dominaria"),
    ("ss-grn", "Guilds of Ravnica"),
    ("ss-rna", "Ravnica Allegiance"),
    ("ss-war", "War of the Spark"),
    ("ss-eld", "Throne of Eldraine"),
    ("ss-thb", "Theros: Beyond Death"),
    ("ss-iko", "koria: Lair of Behemoths"),
    ("ss-znr", "Zendikar Rising"),
    ("ss-khm", "Kaldheim"),
    ("ss-stx", "Strixhaven: School of Mages"),
    ("ss-mid", "Innistrad: Midnight Hunt"),
    ("ss-vow", "Innistrad: Crimson Vow"),
    ("ss-neo", "Kamigawa: Neon Dynasty"),
    ("ss-snc", "Streets of New Capenna"),
    ("ss-dmu", "Dominaria United"),
    ("ss-bro", "The Brothers' War"),
    ("ss-one", "Phyrexia: All Will Be One"),
    ("ss-mom", "March of the Machine"),
    ("ss-mat", "March of the Machine: The Aftermath"),
    ("ss-woe", "Wilds of Eldraine"),
)

DEFAULT_YARA_PATH = "/yara/default.yara"
