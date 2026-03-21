from reporterman.modules.execution.script_executor import check_execution


def test_check_execution():
    test1 = check_execution("efn3rrd")
    test2 = check_execution("1,payload,0,cve")
    test3 = check_execution("0,payload,0,cve")
    test4 = check_execution("1,payload2,1,cve")
    test5 = check_execution("efrwwp,r4dw,0,dcw")

    assert not test1
    assert test2
    assert not test3
    assert test4
    assert not test5
