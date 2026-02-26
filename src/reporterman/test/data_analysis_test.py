import hashlib
from reporterman.modules.data_analysis.data_analysis import get_cve_description


def test_get_cve_description():
    desc1 = get_cve_description("CVE-2019-19234")
    hash1 = hashlib.sha256(desc1.encode("utf-8")).hexdigest()
    expected1 = (
        "d1055f3e1932b1ac8b17eb7878ac5bd0aa5e0d841161f269020062fdb16d2d52"  # noqa
    )
    assert hash1 == expected1

    desc2 = get_cve_description("CVE-2022-1284")
    hash2 = hashlib.sha256(desc2.encode("utf-8")).hexdigest()
    expected2 = (
        "523928561b5f35bcd021e8b4ad8daa26b7bf9e75c422c94f3f358903049efcd1"  # noqa
    )
    assert hash2 == expected2
