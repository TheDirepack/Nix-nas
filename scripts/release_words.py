"""Reviewed words for human-readable release bootstrap passphrases."""

from __future__ import annotations

RELEASE_WORDS: tuple[str, ...] = tuple(
    """
    acorn adobe alder amber anchor apple apron arbor arrow atlas
    badge baker basil beach berry birch blade bloom board brook
    brush cabin cable camel canal cedar chair chalk charm chess
    cider cliff cloud clover coast comet coral crane creek crown
    daisy delta denim depot drift dune eagle earth ember fable
    fern field finch flame flora flute forge frost garden globe
    grape grove harbor hazel heron honey horse ivory jade juniper
    kettle kite lake larch lemon light lilac linen lodge lotus
    maple marsh meadow melon mint moon moss motor navy nectar
    oakleaf oasis ocean olive onyx orbit orchid otter paddle palm
    panda pearl pebble pine plume pond poppy porch prism quartz
    quest raven reed ridge river robin rose ruby sail sage satin
    shell shore silver slate solar sparrow spice spring stone storm
    summit sunset surf swan table teal thyme tiger timber trail
    tulip vale velvet vine violet wave wheat willow wind wing
    winter wren yard yarn zenith alpine apricot aqua ashwood aurora
    autumn bamboo beacon beech biscuit blossom breeze bronze canyon
    caramel cardinal cascade cherry chestnut cobalt copper cosmos
    cotton cove crystal dawn desert domino dragon echo elmwood
    emerald falcon feather fennel firefly fjord forest foxglove
    galaxy ginger glacier granite hawthorn heather horizon iris
    island jasmine lagoon lantern laurel lavender lighthouse lime
    magnolia mango marble marine merlin meteor midnight mosaic
    mountain mulberry myrtle nightfall opal orchard osprey papaya
    parchment peach penguin pepper petal phoenix planet plum prairie
    pumpkin rain rainbow reef ripple rosemary saffron sandbar scarlet
    sequoia shadow skyward snowdrop spruce starling starlight sunflower
    terrace thunder topaz turtle valley vanilla verdant walnut waterfall
    whisper wildflower woodland zephyr almond anise barley bayou
    bluebird briar buttercup cactus canary cinnamon citrus coconut
    compass cricket dahlia dolphin evergreen figwood flamingo freesia
    garnet gingko goldenrod hibiscus iceberg lemongrass mandarin marigold
    nectarine oregano parsley peacock pistachio primrose redwood sandalwood
    sapphire sorrel tamarind tangerine thistle watercolor windmill
    """.split()
)

if len(RELEASE_WORDS) != len(set(RELEASE_WORDS)):
    raise RuntimeError("release passphrase word list contains duplicates")
