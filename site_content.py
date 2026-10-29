"""
Content for "Greek History World", the public face of the honeypot.

REAL_PAGES are genuine, human-readable articles on Greek mythology. They make
the site look like an ordinary fan reference site.

The trap pages (/archive/...) are generated from the same sentences by a
Markov chain, so they read like plausible-but-garbled mythology notes rather
than random word salad.
"""

SITE_NAME = "Greek History World"
TAGLINE = "Myths, legends and the stories behind them"

# Each section: (path, nav label, page title, intro, [(heading, text), ...])
REAL_PAGES = [
    (
        "/olympians", "Olympians", "The Twelve Olympians",
        "The Olympians were the principal gods of the Greek pantheon, said to "
        "live on Mount Olympus, the highest mountain in Greece.",
        [
            ("Zeus", "Zeus was the king of the gods and ruler of the sky and "
             "thunder. He was the son of the Titans Cronus and Rhea. Cronus "
             "swallowed his children at birth, but Rhea hid the infant Zeus on "
             "Crete, and Zeus later forced his father to release his siblings. "
             "His symbols were the thunderbolt, the eagle and the oak tree."),
            ("Hera", "Hera was the queen of the gods and the goddess of "
             "marriage and family. She was both the sister and the wife of "
             "Zeus. The peacock was sacred to her, and its tail was said to "
             "carry the hundred eyes of her watchman Argus."),
            ("Poseidon", "Poseidon ruled the sea and was also the god of "
             "earthquakes and horses. He carried a trident. He competed with "
             "Athena to become patron of Athens: he struck the rock and "
             "produced a salt-water spring, but the Athenians preferred "
             "Athena's gift of the olive tree."),
            ("Athena", "Athena was the goddess of wisdom, crafts and military "
             "strategy. She was born fully grown and armored from the head of "
             "Zeus. The owl and the olive tree were her symbols, and the "
             "Parthenon in Athens was built in her honor."),
            ("Apollo and Artemis", "Apollo and Artemis were twins, the "
             "children of Zeus and Leto, born on the island of Delos. Apollo "
             "was the god of music, prophecy and healing, and his oracle at "
             "Delphi was the most famous in the Greek world. Artemis was the "
             "goddess of the hunt and the wilderness."),
            ("Hermes", "Hermes was the messenger of the gods and the protector "
             "of travelers, merchants and thieves. On the day he was born he "
             "stole fifty cattle from Apollo and invented the lyre from a "
             "tortoise shell, which he gave to Apollo to make peace."),
            ("Aphrodite", "Aphrodite was the goddess of love and beauty. "
             "According to the poet Hesiod she was born from the foam of the "
             "sea and came ashore at Cyprus. She was married to Hephaestus, "
             "the god of the forge."),
            ("Dionysus", "Dionysus was the god of wine, festivity and theater. "
             "Athenian drama grew out of festivals held in his honor. In some "
             "lists he takes the place of Hestia, goddess of the hearth, among "
             "the twelve Olympians."),
        ],
    ),
    (
        "/heroes", "Heroes", "Heroes of Greek Myth",
        "Greek heroes were mortals, often with one divine parent, whose "
        "deeds were celebrated in poetry and cult.",
        [
            ("Heracles", "Heracles, called Hercules by the Romans, was the son "
             "of Zeus and the mortal Alcmene. To atone for a crime he served "
             "King Eurystheus and completed twelve labors, including slaying "
             "the Nemean lion, killing the Lernaean Hydra, cleaning the Augean "
             "stables in a single day and capturing Cerberus from the "
             "Underworld."),
            ("Perseus", "Perseus beheaded the Gorgon Medusa. Athena gave him a "
             "polished shield so he could look at her reflection instead of "
             "her face, and Hermes lent him winged sandals. On his way home he "
             "rescued the princess Andromeda from a sea monster."),
            ("Theseus", "Theseus sailed to Crete and killed the Minotaur in "
             "the Labyrinth, finding his way out with a ball of thread given "
             "to him by Ariadne. He forgot to change his black sails to white, "
             "and his father Aegeus, believing him dead, threw himself into "
             "the sea that now bears his name, the Aegean."),
            ("Odysseus", "Odysseus, king of Ithaca, devised the wooden horse "
             "that ended the Trojan War. His journey home took ten years and "
             "is told in Homer's Odyssey. He escaped the Cyclops Polyphemus by "
             "telling him his name was Nobody."),
            ("Achilles", "Achilles was the greatest Greek warrior at Troy. His "
             "mother Thetis dipped him in the river Styx to make him "
             "invulnerable, except for the heel by which she held him. He "
             "killed the Trojan prince Hector and was later killed by an "
             "arrow shot by Paris."),
            ("Jason", "Jason led the Argonauts aboard the ship Argo to the "
             "kingdom of Colchis to win the Golden Fleece. He succeeded with "
             "the help of the sorceress Medea, daughter of the king."),
        ],
    ),
    (
        "/creatures", "Creatures", "Monsters and Creatures",
        "Greek myth is full of monsters, many of them born from the "
        "primordial gods or created as punishments.",
        [
            ("Medusa", "Medusa was one of the three Gorgons, and the only "
             "mortal one. Anyone who looked at her face was turned to stone. "
             "When Perseus beheaded her, the winged horse Pegasus sprang from "
             "her neck."),
            ("The Minotaur", "The Minotaur had the body of a man and the head "
             "of a bull. King Minos of Crete kept it in the Labyrinth, a maze "
             "built by the craftsman Daedalus, and fed it young men and women "
             "sent as tribute from Athens."),
            ("The Hydra", "The Lernaean Hydra was a many-headed serpent. For "
             "every head that was cut off, two more grew back. Heracles "
             "defeated it with the help of his nephew Iolaus, who burned each "
             "neck after its head was cut off."),
            ("Cerberus", "Cerberus was the multi-headed dog that guarded the "
             "gates of the Underworld, usually described with three heads. He "
             "let the dead enter but never allowed them to leave."),
            ("The Chimera", "The Chimera was a fire-breathing creature with "
             "the body of a lion, a goat's head rising from its back and a "
             "serpent for a tail. The hero Bellerophon killed it while riding "
             "Pegasus."),
            ("The Sirens", "The Sirens lured sailors to their deaths with "
             "irresistible songs. Odysseus had his crew plug their ears with "
             "beeswax and tie him to the mast so he could hear the song and "
             "survive."),
        ],
    ),
    (
        "/myths", "Myths", "Famous Myths",
        "Many Greek myths explained the natural world or warned against "
        "pride, which the Greeks called hubris.",
        [
            ("Prometheus", "The Titan Prometheus stole fire from the gods and "
             "gave it to humanity. As punishment Zeus chained him to a rock, "
             "where an eagle ate his liver every day, and every night the "
             "liver grew back. Heracles eventually set him free."),
            ("Pandora", "Pandora was the first woman, created by the gods. She "
             "opened a jar, not a box, and released all the evils into the "
             "world, leaving only hope inside. The word box comes from a "
             "sixteenth-century mistranslation."),
            ("Persephone", "Hades carried Persephone off to the Underworld. "
             "Her mother Demeter, goddess of the harvest, grieved and let the "
             "crops fail. Because Persephone had eaten pomegranate seeds, she "
             "had to spend part of each year below, which the Greeks used to "
             "explain the seasons."),
            ("Orpheus and Eurydice", "The musician Orpheus traveled to the "
             "Underworld to bring back his wife Eurydice. Hades agreed on the "
             "condition that Orpheus not look back until they reached the "
             "surface. He looked back just before the end, and lost her "
             "forever."),
            ("Icarus", "Daedalus built wings of feathers and wax so that he "
             "and his son Icarus could escape Crete. Icarus ignored his "
             "father's warning, flew too close to the sun, and fell into the "
             "sea when the wax melted."),
            ("The Trojan War", "The goddess Eris threw a golden apple marked "
             "for the fairest. Paris of Troy awarded it to Aphrodite, who "
             "promised him Helen, the wife of King Menelaus of Sparta. Her "
             "abduction led to a ten-year war that ended when the Greeks hid "
             "soldiers inside a wooden horse."),
        ],
    ),
]

FACTS = [
    "The Aegean Sea is named after King Aegeus, father of Theseus.",
    "The word panic comes from Pan, the goat-legged god of the wild.",
    "The ancient Olympic Games were held at Olympia in honor of Zeus, "
    "traditionally beginning in 776 BC.",
    "The Titan Atlas was condemned to hold up the sky on his shoulders.",
    "To tantalize comes from Tantalus, who stood in water he could never drink.",
    "Nike was the Greek goddess of victory.",
    "Arachne lost a weaving contest with Athena and was turned into a spider.",
    "King Midas washed away his golden touch in the river Pactolus.",
    "Sisyphus was condemned to roll a boulder uphill forever.",
    "The nymph Echo could only repeat the last words spoken to her.",
]

# Vocabulary for trap-page titles and URL slugs.
NAMES = ("Zeus Hera Poseidon Athena Apollo Artemis Hermes Aphrodite Ares "
         "Hephaestus Demeter Dionysus Hades Persephone Heracles Perseus Theseus "
         "Odysseus Achilles Jason Medea Ariadne Daedalus Icarus Orpheus "
         "Prometheus Pandora Medusa Pegasus Cerberus Minos Helen Hector Paris "
         "Penelope Atlas Cronus Rhea Eurydice Bellerophon").split()
PLACES = ("Olympus Delphi Athens Sparta Crete Troy Ithaca Thebes Corinth Argos "
          "Delos Colchis Mycenae Olympia Knossos").split()
THINGS = ("labyrinth oracle trident fleece lyre thunderbolt chariot shield "
          "underworld voyage labors prophecy temple festival curse riddle "
          "harvest sacrifice").split()
TITLE_TEMPLATES = (
    "{name} and the {thing}",
    "Notes on {name}",
    "The Legend of {name} at {place}",
    "{place} in the Age of Heroes",
    "Why {name} Visited {place}",
    "Lesser-Known Tales of {name}",
    "The {thing} of {place}",
)


def corpus_sentences():
    """Every sentence from the real pages, for training the Markov chain."""
    text = " ".join(
        intro + " " + " ".join(body for _, body in sections)
        for _, _, _, intro, sections in REAL_PAGES
    ) + " " + " ".join(FACTS)
    out, cur = [], []
    for word in text.split():
        cur.append(word)
        if word.endswith((".", "!", "?")):
            out.append(cur)
            cur = []
    return out
