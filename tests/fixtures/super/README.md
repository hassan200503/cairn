# Golden super image fixture

`golden_super.img` (SHA-256
`8eef7728358856d4c8cf428d1591b3c1d0c02a9d0bf485b418f167ba0d6d897f`) was
generated with the official AOSP `lpmake` host tool built from pinned source
(see `tools/oracle/PINNED.md`; system/extras
`fc2494a2abd7ab21774d03deb09c1362bbb0bba8`, system/core
`a3b721a32242006b59cb12bd62c9133632af3a2d`).

Generating command (deterministic; partition image contents are zeros):

```console
dd if=/dev/zero of=ba.img bs=64K count=1
dd if=/dev/zero of=bb.img bs=64K count=1
lpmake --metadata-size 4096 --metadata-slots 2 --device-size 1048576 \
  --alignment 4096 \
  --group tg_a:524288 --group tg_b:524288 \
  --partition boot_a:none:65536:tg_a --image boot_a=ba.img \
  --partition system_a:readonly:196608:tg_a --image system_a=ba.img \
  --partition boot_b:none:65536:tg_b --image boot_b=bb.img \
  --partition system_b:readonly:196608:tg_b --image system_b=bb.img \
  --virtual-ab --output golden_super.img
```

The fixture carries no device-derived data; it is synthetic. The differential
tests that require the oracle binary live in `tests/test_super_meta.py` and
skip when `lpmake` is not on the path; the golden-fixture and negative tests
run everywhere.
